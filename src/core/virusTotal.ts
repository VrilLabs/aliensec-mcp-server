/**
 * AlienSec MCP Server - VirusTotal Integration Module
 * 
 * Provides VirusTotal API integration with rate limiting, circuit breaker pattern,
 * and automatic API key rotation. Note: VirusTotal ToS prohibits using multiple API
 * keys to bypass rate limits. This implementation respects those limits.
 */

import fetch from 'node-fetch';
import { z } from 'zod';
import {
  VirusTotalResult,
  VirusTotalEngineResult,
  VirusTotalAPIError,
  VirusTotalConfig,
  VirusTotalAPIError as VirusTotalAPIErrorType,
} from '../types';
import { getConfig } from '../config';
import { getDatabase } from '../database';
import { AlienVaultAPIError, ConfigurationError } from '../types';

// ============================================================================
// VirusTotal API Types & Schemas
// ============================================================================

const virusTotalScanResponseSchema = z.object({
  data: z.object({
    id: z.string(),
    type: z.string(),
    attributes: z.object({
      status: z.string(),
      last_analysis_stats: z.object({
        malicious: z.number().optional(),
        suspicious: z.number().optional(),
        undetected: z.number().optional(),
        harmless: z.number().optional(),
        timeout: z.number().optional(),
      }).optional(),
      last_analysis_results: z.record(
        z.object({
          category: z.string().optional(),
          engine_name: z.string().optional(),
          engine_version: z.string().optional(),
          method: z.string().optional(),
          result: z.string().optional(),
        })
      ).optional(),
    }),
  }),
});

const virusTotalErrorResponseSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
  }),
});

// ============================================================================
// Circuit Breaker Implementation
// ============================================================================

/**
 * Circuit breaker state for a specific API key.
 */
interface CircuitBreakerState {
  isOpen: boolean;
  isHalfOpen: boolean;
  lastFailure?: Date;
  lastSuccess?: Date;
  failureCount: number;
  successCount: number;
  timeoutUntil?: Date;
}

/**
 * Circuit breaker configuration.
 */
interface CircuitBreakerConfig {
  failureThreshold: number;
  resetTimeoutSeconds: number;
  halfOpenTestCount: number;
}

const DEFAULT_CIRCUIT_BREAKER_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  resetTimeoutSeconds: 300, // 5 minutes
  halfOpenTestCount: 1,
};

/**
 * Circuit breaker class for managing API key states.
 */
export class VirusTotalCircuitBreaker {
  private readonly states: Map<number, CircuitBreakerState> = new Map();
  private readonly config: CircuitBreakerConfig;

  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    this.config = {
      ...DEFAULT_CIRCUIT_BREAKER_CONFIG,
      ...config,
    };
  }

  /**
   * Checks if a specific API key is allowed to make a request.
   */
  canExecute(apiKeyIndex: number): boolean {
    const state = this.states.get(apiKeyIndex);
    
    if (!state) {
      // No state recorded, allow execution
      return true;
    }

    if (state.isOpen) {
      // Circuit is open, check if timeout has elapsed
      if (state.timeoutUntil && new Date() >= state.timeoutUntil) {
        // Timeout elapsed, transition to half-open
        state.isOpen = false;
        state.isHalfOpen = true;
        state.failureCount = 0;
        state.successCount = 0;
        return true;
      }
      return false;
    }

    return true;
  }

  /**
   * Records a successful request for a specific API key.
   */
  recordSuccess(apiKeyIndex: number): void {
    const state = this.states.get(apiKeyIndex) || this.createState(apiKeyIndex);
    state.lastSuccess = new Date();
    state.successCount++;
    
    // If we're in half-open state and the request succeeded, close the circuit
    if (state.isHalfOpen && state.successCount >= this.config.halfOpenTestCount) {
      state.isHalfOpen = false;
      state.failureCount = 0;
      state.successCount = 0;
    }

    this.states.set(apiKeyIndex, state);
  }

  /**
   * Records a failed request for a specific API key.
   */
  recordFailure(apiKeyIndex: number, isRateLimit: boolean = false): void {
    const state = this.states.get(apiKeyIndex) || this.createState(apiKeyIndex);
    state.lastFailure = new Date();
    state.failureCount++;

    if (state.failureCount >= this.config.failureThreshold || isRateLimit) {
      // Open the circuit
      state.isOpen = true;
      state.isHalfOpen = false;
      state.timeoutUntil = new Date(
        Date.now() + this.config.resetTimeoutSeconds * 1000
      );
      state.failureCount = 0;
    }

    this.states.set(apiKeyIndex, state);
  }

  /**
   * Creates a new circuit breaker state for an API key.
   */
  private createState(apiKeyIndex: number): CircuitBreakerState {
    return {
      isOpen: false,
      isHalfOpen: false,
      failureCount: 0,
      successCount: 0,
    };
  }

  /**
   * Gets the current state for an API key.
   */
  getState(apiKeyIndex: number): CircuitBreakerState {
    return this.states.get(apiKeyIndex) || this.createState(apiKeyIndex);
  }

  /**
   * Resets the circuit breaker state for an API key.
   */
  reset(apiKeyIndex: number): void {
    this.states.delete(apiKeyIndex);
  }

  /**
   * Resets all circuit breaker states.
   */
  resetAll(): void {
    this.states.clear();
  }

  /**
   * Gets all current states.
   */
  getAllStates(): Map<number, CircuitBreakerState> {
    return new Map(this.states);
  }
}

// ============================================================================
// VirusTotal API Client
// ============================================================================

/**
 * VirusTotal API client with automatic rate limiting and circuit breaker.
 */
export class VirusTotalClient {
  private readonly config: VirusTotalConfig;
  private readonly circuitBreaker: VirusTotalCircuitBreaker;
  private readonly rateLimiter: RateLimiter;
  private readonly database;

  // Track request counts for rate limiting
  private lastRequestTimestamps: Map<number, Date[]> = new Map();
  private dailyRequestCounts: Map<number, number> = new Map();

  constructor(config: VirusTotalConfig = getConfig().virusTotal) {
    this.config = config;
    this.circuitBreaker = new VirusTotalCircuitBreaker({
      resetTimeoutSeconds: config.circuitBreakerTimeout,
    });
    this.rateLimiter = new RateLimiter(config.rateLimitPerMinute);
    this.database = getDatabase();
  }

  /**
   * Scans a file or URL using VirusTotal.
   */
  async scan(
    resource: string,
    apiKeyIndex: number = 0,
    options: { wait?: boolean } = {}
  ): Promise<VirusTotalResult> {
    const apiKey = this.getApiKey(apiKeyIndex);

    // Check circuit breaker
    if (!this.circuitBreaker.canExecute(apiKeyIndex)) {
      const state = this.circuitBreaker.getState(apiKeyIndex);
      throw new VirusTotalAPIErrorType(
        `API key ${apiKeyIndex} is blocked by circuit breaker until ${state.timeoutUntil?.toISOString()}`,
        429,
        true,
        false,
        { apiKeyIndex, timeoutUntil: state.timeoutUntil }
      );
    }

    // Check rate limiting
    await this.rateLimiter.wait(apiKeyIndex, options.wait);

    // Check daily limit
    this.checkDailyLimit(apiKeyIndex);

    const startTime = Date.now();
    
    try {
      const response = await this.makeRequest(
        apiKey,
        `${this.config.baseUrl}/files`,
        {
          method: 'POST',
          headers: {
            'x-apikey': apiKey,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ hash: resource }),
        }
      );

      // Record success
      this.circuitBreaker.recordSuccess(apiKeyIndex);
      this.rateLimiter.recordRequest(apiKeyIndex);
      this.recordDailyRequest(apiKeyIndex);

      // Log the request
      this.logRequest(apiKeyIndex, apiKey, 'scan', response.status, Date.now() - startTime, true, undefined, '/files');

      const data = await response.json();
      const parsed = virusTotalScanResponseSchema.parse(data);

      return this.transformToVirusTotalResult(parsed, apiKeyIndex);
    } catch (error) {
      const isRateLimit = this.isRateLimitError(error);
      const isQuotaExceeded = this.isQuotaExceededError(error);

      // Record failure
      this.circuitBreaker.recordFailure(apiKeyIndex, isRateLimit);
      this.rateLimiter.recordRequest(apiKeyIndex);

      // Log the failed request
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logRequest(apiKeyIndex, apiKey, 'scan', 0, Date.now() - startTime, false, errorMessage, '/files');

      throw new VirusTotalAPIErrorType(
        errorMessage,
        0,
        isRateLimit,
        isQuotaExceeded,
        { apiKeyIndex, isRateLimit, isQuotaExceeded }
      );
    }
  }

  /**
   * Gets analysis results for a file hash.
   */
  async getAnalysis(
    hash: string,
    apiKeyIndex: number = 0,
    options: { wait?: boolean } = {}
  ): Promise<VirusTotalResult> {
    const apiKey = this.getApiKey(apiKeyIndex);

    // Check circuit breaker
    if (!this.circuitBreaker.canExecute(apiKeyIndex)) {
      const state = this.circuitBreaker.getState(apiKeyIndex);
      throw new VirusTotalAPIErrorType(
        `API key ${apiKeyIndex} is blocked by circuit breaker until ${state.timeoutUntil?.toISOString()}`,
        429,
        true,
        false,
        { apiKeyIndex, timeoutUntil: state.timeoutUntil }
      );
    }

    // Check rate limiting
    await this.rateLimiter.wait(apiKeyIndex, options.wait);

    // Check daily limit
    this.checkDailyLimit(apiKeyIndex);

    const startTime = Date.now();

    try {
      const response = await this.makeRequest(
        apiKey,
        `${this.config.baseUrl}/analyses/${hash}`,
        {
          headers: {
            'x-apikey': apiKey,
          },
        }
      );

      // Record success
      this.circuitBreaker.recordSuccess(apiKeyIndex);
      this.rateLimiter.recordRequest(apiKeyIndex);
      this.recordDailyRequest(apiKeyIndex);

      // Log the request
      this.logRequest(apiKeyIndex, apiKey, 'lookup', response.status, Date.now() - startTime, true, undefined, `/analyses/${hash}`);

      const data = await response.json();
      const parsed = virusTotalScanResponseSchema.parse(data);

      return this.transformToVirusTotalResult(parsed, apiKeyIndex);
    } catch (error) {
      const isRateLimit = this.isRateLimitError(error);
      const isQuotaExceeded = this.isQuotaExceededError(error);

      // Record failure
      this.circuitBreaker.recordFailure(apiKeyIndex, isRateLimit);
      this.rateLimiter.recordRequest(apiKeyIndex);

      // Log the failed request
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logRequest(apiKeyIndex, apiKey, 'lookup', 0, Date.now() - startTime, false, errorMessage, `/analyses/${hash}`);

      throw new VirusTotalAPIErrorType(
        errorMessage,
        0,
        isRateLimit,
        isQuotaExceeded,
        { apiKeyIndex, isRateLimit, isQuotaExceeded }
      );
    }
  }

  /**
   * Makes an HTTP request to the VirusTotal API.
   */
  private async makeRequest(
    apiKey: string,
    url: string,
    options: RequestInit = {}
  ): Promise<Response> {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await this.tryParseError(response);
      throw new Error(
        errorData?.error?.message || 
        `VirusTotal API request failed with status ${response.status}`
      );
    }

    return response;
  }

  /**
   * Tries to parse the error response from VirusTotal.
   */
  private async tryParseError(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  /**
   * Checks if an error is a rate limit error.
   */
  private isRateLimitError(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      return (
        message.includes('rate limit') ||
        message.includes('too many requests') ||
        message.includes('429')
      );
    }
    return false;
  }

  /**
   * Checks if an error is a quota exceeded error.
   */
  private isQuotaExceededError(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();
      return (
        message.includes('quota exceeded') ||
        message.includes('quota') ||
        message.includes('402') ||
        message.includes('403')
      );
    }
    return false;
  }

  /**
   * Gets an API key by index.
   */
  private getApiKey(index: number): string {
    if (index < 0 || index >= this.config.apiKeys.length) {
      throw new ConfigurationError(`Invalid API key index: ${index}`);
    }
    return this.config.apiKeys[index];
  }

  /**
   * Transforms VirusTotal API response to our internal format.
   */
  private transformToVirusTotalResult(
    data: z.infer<typeof virusTotalScanResponseSchema>,
    apiKeyIndex: number
  ): VirusTotalResult {
    const id = data.data.id;
    const attributes = data.data.attributes;
    const lastAnalysisStats = attributes.last_analysis_stats || {};
    const lastAnalysisResults = attributes.last_analysis_results || {};

    const results: Record<string, VirusTotalEngineResult> = {};
    
    for (const [engineName, result] of Object.entries(lastAnalysisResults)) {
      results[engineName] = {
        engine: engineName,
        name: result.category || 'unknown',
        category: result.category as any,
        confidence: result.category ? 100 : 0,
        raw: result,
      };
    }

    return {
      scanId: id,
      apiKeyIndex,
      timestamp: new Date(),
      positives: lastAnalysisStats.malicious || 0,
      total: Object.keys(lastAnalysisResults).length,
      results,
      permalink: `${this.config.baseUrl.replace('/api/v3', '')}/analysis/${id}`,
    };
  }

  /**
   * Logs an API request to the database.
   */
  private logRequest(
    apiKeyIndex: number,
    apiKey: string,
    requestType: 'scan' | 'lookup' | 'report' | 'other',
    responseStatus: number,
    responseTimeMs: number,
    success: boolean,
    errorMessage?: string,
    endpoint?: string
  ): void {
    try {
      const db = getDatabase();
      const repo = db.getAPILogRepository();
      repo.logRequest(
        apiKeyIndex,
        apiKey,
        requestType,
        responseStatus,
        responseTimeMs,
        success,
        errorMessage,
        endpoint
      );
    } catch {
      // Ignore database logging errors to prevent affecting the main flow
    }
  }

  /**
   * Records a daily request for rate limiting.
   */
  private recordDailyRequest(apiKeyIndex: number): void {
    const today = new Date().toISOString().split('T')[0];
    const key = `${apiKeyIndex}:${today}`;
    this.dailyRequestCounts.set(
      apiKeyIndex,
      (this.dailyRequestCounts.get(apiKeyIndex) || 0) + 1
    );
  }

  /**
   * Checks if the daily limit has been reached for an API key.
   */
  private checkDailyLimit(apiKeyIndex: number): void {
    const dailyCount = this.dailyRequestCounts.get(apiKeyIndex) || 0;
    if (dailyCount >= this.config.dailyLimit) {
      throw new VirusTotalAPIErrorType(
        `Daily limit of ${this.config.dailyLimit} requests exceeded for API key ${apiKeyIndex}`,
        429,
        false,
        true,
        { apiKeyIndex, dailyCount, dailyLimit: this.config.dailyLimit }
      );
    }
  }
}

// ============================================================================
// Rate Limiter Implementation
// ============================================================================

/**
 * Token bucket rate limiter for API requests.
 */
class RateLimiter {
  private readonly rateLimitPerMinute: number;
  private readonly intervals: Map<number, Date[]> = new Map();
  private readonly tokens: Map<number, number> = new Map();
  private readonly lastRefill: Map<number, Date> = new Map();

  constructor(rateLimitPerMinute: number) {
    this.rateLimitPerMinute = rateLimitPerMinute;
  }

  /**
   * Waits if necessary to stay within rate limits.
   */
  async wait(apiKeyIndex: number, wait: boolean = true): Promise<void> {
    this.refillTokens(apiKeyIndex);

    let tokens = this.tokens.get(apiKeyIndex) ?? this.rateLimitPerMinute;

    if (tokens <= 0) {
      if (!wait) {
        throw new VirusTotalAPIErrorType(
          `Rate limit exceeded for API key ${apiKeyIndex}`,
          429,
          true,
          false,
          { apiKeyIndex, tokens }
        );
      }

      // Calculate how long to wait
      const last = this.lastRefill.get(apiKeyIndex);
      if (last) {
        const elapsed = (Date.now() - last.getTime()) / 1000; // seconds
        const waitTime = Math.max(0, 60 / this.rateLimitPerMinute - elapsed);
        
        if (waitTime > 0) {
          await new Promise((resolve) => setTimeout(resolve, waitTime * 1000));
          this.refillTokens(apiKeyIndex);
        }
      }
    }
  }

  /**
   * Records a request and consumes a token.
   */
  recordRequest(apiKeyIndex: number): void {
    this.refillTokens(apiKeyIndex);
    const tokens = this.tokens.get(apiKeyIndex) ?? this.rateLimitPerMinute;
    this.tokens.set(apiKeyIndex, Math.max(0, tokens - 1));
  }

  /**
   * Refills tokens based on elapsed time.
   */
  private refillTokens(apiKeyIndex: number): void {
    const now = new Date();
    const last = this.lastRefill.get(apiKeyIndex) || now;
    
    const elapsedSeconds = (now.getTime() - last.getTime()) / 1000;
    const tokensToAdd = Math.floor(elapsedSeconds * (this.rateLimitPerMinute / 60));

    if (tokensToAdd > 0) {
      const currentTokens = this.tokens.get(apiKeyIndex) ?? this.rateLimitPerMinute;
      const newTokens = Math.min(
        this.rateLimitPerMinute,
        currentTokens + tokensToAdd
      );
      
      this.tokens.set(apiKeyIndex, newTokens);
      this.lastRefill.set(apiKeyIndex, now);
    }
  }
}

// ============================================================================
// Singleton Client Instance
// ============================================================================

let virusTotalClientInstance: VirusTotalClient | null = null;

/**
 * Gets the singleton VirusTotal client instance.
 */
export function getVirusTotalClient(): VirusTotalClient {
  if (!virusTotalClientInstance) {
    virusTotalClientInstance = new VirusTotalClient();
  }
  return virusTotalClientInstance;
}

/**
 * Resets the singleton VirusTotal client instance. Useful for testing.
 */
export function resetVirusTotalClient(): void {
  virusTotalClientInstance = null;
}

/**
 * Creates a new VirusTotal client with custom configuration.
 * Useful for testing or multi-tenant scenarios.
 */
export function createVirusTotalClient(config: VirusTotalConfig): VirusTotalClient {
  return new VirusTotalClient(config);
}

// ============================================================================
// Export
// ============================================================================

export {
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  RateLimiter,
};
