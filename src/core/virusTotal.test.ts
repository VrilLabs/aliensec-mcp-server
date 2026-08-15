/**
 * AlienSec MCP Server - VirusTotal Client Tests
 *
 * Tests for VirusTotal API integration, circuit breaker, and rate limiter functionality.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock config and database modules BEFORE any imports that use them
// This is necessary due to Vitest hoisting behavior
// Note: These mocks will only affect this test file due to Vitest's isolation mode
vi.mock('../config', () => ({
  getConfig: vi.fn(),
  resetConfig: vi.fn(),
  createConfig: vi.fn(),
}));

// Mock database module - this is isolated to this test file
vi.mock('../database', () => ({
  getDatabase: vi.fn(),
  resetDatabase: vi.fn(),
  createDatabase: vi.fn(),
  AlienSecDatabase: class {},
}));

import {
  VirusTotalClient,
  VirusTotalCircuitBreaker,
  RateLimiter,
  getVirusTotalClient,
  resetVirusTotalClient,
  createVirusTotalClient,
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
} from './virusTotal';
import { VirusTotalConfig, VirusTotalResult, VirusTotalAPIError } from '../types';
import { getConfig } from '../config';
import { getDatabase, resetDatabase } from '../database';

// Note: Global mocks are already set up in src/test/setup.ts
// for better-sqlite3-multiple-ciphers, the global fetch API, and pino

// Access the globally mocked fetch
const mockFetch = vi.mocked(fetch);

describe('VirusTotal Module', () => {
  let testConfig: VirusTotalConfig;

  beforeEach(() => {
    resetVirusTotalClient();
    resetDatabase();
    vi.clearAllMocks();

    // Setup test configuration
    testConfig = {
      apiKeys: ['test-vt-key-1', 'test-vt-key-2', 'test-vt-key-3'],
      baseUrl: 'https://www.virustotal.com/api/v3',
      rateLimitPerMinute: 4,
      dailyLimit: 500,
      circuitBreakerTimeout: 300,
    };

    vi.mocked(getConfig).mockReturnValue({
      virusTotal: testConfig,
      server: { name: 'test', version: '1.0', debug: false, logLevel: 'info' },
      alienVault: { apiKey: 'test-av-key', baseUrl: 'https://api.agent.otxb.io', defaultRegion: 'us-east-1' },
      database: { path: ':memory:', timeout: 5000 },
    } as any);

    // Mock database
    const mockDb = {
      getScanRepository: () => ({}),
      getCircuitBreakerRepository: () => ({}),
      getAPILogRepository: () => ({
        logRequest: vi.fn().mockResolvedValue({}),
      }),
    };
    vi.mocked(getDatabase).mockReturnValue(mockDb as any);
  });

  afterEach(() => {
    resetVirusTotalClient();
    resetDatabase();
    vi.restoreAllMocks();
  });

  describe('Circuit Breaker', () => {
    describe('VirusTotalCircuitBreaker', () => {
      let circuitBreaker: VirusTotalCircuitBreaker;

      beforeEach(() => {
        circuitBreaker = new VirusTotalCircuitBreaker();
      });

      describe('Initial State', () => {
        it('should allow execution for unknown API key index', () => {
          const canExecute = circuitBreaker.canExecute(0);
          expect(canExecute).toBe(true);
        });

        it('should return default state for unknown API key index', () => {
          const state = circuitBreaker.getState(0);
          expect(state.isOpen).toBe(false);
          expect(state.failureCount).toBe(0);
          expect(state.successCount).toBe(0);
        });
      });

      describe('canExecute', () => {
        it('should allow execution when circuit is closed', () => {
          const canExecute = circuitBreaker.canExecute(0);
          expect(canExecute).toBe(true);
        });

        it('should allow execution when circuit is open but timeout has elapsed', () => {
          // Force the circuit to be open with a past timeout
          const pastDate = new Date(Date.now() - 10000); // 10 seconds ago
          circuitBreaker.recordFailure(0, true);

          // Manually set the state to open with past timeout
          const state = circuitBreaker.getState(0);
          state.isOpen = true;
          state.timeoutUntil = pastDate;

          const canExecute = circuitBreaker.canExecute(0);
          expect(canExecute).toBe(true);
        });

        it('should block execution when circuit is open and timeout not elapsed', () => {
          // Record enough failures to open the circuit
          for (let i = 0; i < 5; i++) {
            circuitBreaker.recordFailure(0);
          }

          const canExecute = circuitBreaker.canExecute(0);
          expect(canExecute).toBe(false);
        });
      });

      describe('recordSuccess', () => {
        it('should record successful requests', () => {
          circuitBreaker.recordSuccess(0);
          const state = circuitBreaker.getState(0);
          expect(state.successCount).toBe(1);
          expect(state.lastSuccess).toBeDefined();
        });

        it('should reset counts after half-open test count is reached', () => {
          const cb = new VirusTotalCircuitBreaker({
            failureThreshold: 3,
            resetTimeoutSeconds: 0, // Immediate timeout for testing
            halfOpenTestCount: 2,
          });

          // Open the circuit
          for (let i = 0; i < 3; i++) {
            cb.recordFailure(0);
          }

          // Transition to half-open by calling canExecute (which checks timeout)
          // Since resetTimeoutSeconds is 0, the timeout is immediate
          cb.canExecute(0);

          // Record successes in half-open state to close the circuit
          cb.recordSuccess(0);
          cb.recordSuccess(0);

          const state = cb.getState(0);
          expect(state.successCount).toBe(0);
          expect(state.failureCount).toBe(0);
        });
      });

      describe('recordFailure', () => {
        it('should record failed requests', () => {
          circuitBreaker.recordFailure(0);
          const state = circuitBreaker.getState(0);
          expect(state.failureCount).toBe(1);
          expect(state.lastFailure).toBeDefined();
        });

        it('should open circuit after reaching failure threshold', () => {
          const cb = new VirusTotalCircuitBreaker({
            failureThreshold: 3,
            resetTimeoutSeconds: 60,
            halfOpenTestCount: 1,
          });

          // Record failures up to threshold
          for (let i = 0; i < 3; i++) {
            cb.recordFailure(0);
          }

          const state = cb.getState(0);
          expect(state.isOpen).toBe(true);
          expect(state.timeoutUntil).toBeDefined();
        });

        it('should open circuit immediately for rate limit errors', () => {
          circuitBreaker.recordFailure(0, true);
          const state = circuitBreaker.getState(0);
          expect(state.isOpen).toBe(true);
        });
      });

      describe('reset', () => {
        it('should reset state for specific API key', () => {
          circuitBreaker.recordFailure(0);
          circuitBreaker.reset(0);

          const state = circuitBreaker.getState(0);
          expect(state.isOpen).toBe(false);
          expect(state.failureCount).toBe(0);
        });

        it('should not affect other API keys', () => {
          circuitBreaker.recordFailure(0);
          circuitBreaker.recordFailure(1);
          circuitBreaker.reset(0);

          const state0 = circuitBreaker.getState(0);
          const state1 = circuitBreaker.getState(1);
          expect(state0.failureCount).toBe(0);
          expect(state1.failureCount).toBe(1);
        });
      });

      describe('resetAll', () => {
        it('should reset all states', () => {
          circuitBreaker.recordFailure(0);
          circuitBreaker.recordFailure(1);
          circuitBreaker.recordSuccess(0);

          circuitBreaker.resetAll();

          const state0 = circuitBreaker.getState(0);
          const state1 = circuitBreaker.getState(1);
          expect(state0.failureCount).toBe(0);
          expect(state1.failureCount).toBe(0);
        });
      });

      describe('getAllStates', () => {
        it('should return all current states', () => {
          circuitBreaker.recordFailure(0);
          circuitBreaker.recordSuccess(1);

          const allStates = circuitBreaker.getAllStates();
          expect(allStates.size).toBeGreaterThan(0);
        });
      });
    });

    describe('DEFAULT_CIRCUIT_BREAKER_CONFIG', () => {
      it('should have correct default values', () => {
        expect(DEFAULT_CIRCUIT_BREAKER_CONFIG.failureThreshold).toBe(5);
        expect(DEFAULT_CIRCUIT_BREAKER_CONFIG.resetTimeoutSeconds).toBe(300);
        expect(DEFAULT_CIRCUIT_BREAKER_CONFIG.halfOpenTestCount).toBe(1);
      });
    });
  });

  describe('Rate Limiter', () => {
    let rateLimiter: RateLimiter;

    beforeEach(() => {
      rateLimiter = new RateLimiter(4); // 4 requests per minute
    });

    describe('Initial State', () => {
      it('should have tokens equal to rate limit on first request', async () => {
        await rateLimiter.wait(0);
        // The limiter should allow the first request without waiting
        // since tokens are initially full
      });

      it('should record requests and consume tokens', () => {
        rateLimiter.recordRequest(0);
        // We can't directly check the token count, but we can verify
        // that recording doesn't throw
      });
    });

    describe('wait', () => {
      it('should not throw when tokens are available', async () => {
        await expect(rateLimiter.wait(0)).resolves.not.toThrow();
      });

      it('should throw when tokens are depleted and wait is false', async () => {
        // Consume all tokens
        for (let i = 0; i < 4; i++) {
          rateLimiter.recordRequest(0);
        }

        await expect(rateLimiter.wait(0, false)).rejects.toThrow();
      });
    });

    describe('recordRequest', () => {
      it('should not throw when called', () => {
        expect(() => rateLimiter.recordRequest(0)).not.toThrow();
      });

      it('should handle multiple API keys independently', () => {
        rateLimiter.recordRequest(0);
        rateLimiter.recordRequest(1);
        // Both should work without errors
      });
    });
  });

  describe('VirusTotalClient', () => {
    let client: VirusTotalClient;

    beforeEach(() => {
      client = new VirusTotalClient(testConfig);
    });

    describe('Constructor', () => {
      it('should accept custom configuration', () => {
        const customConfig: VirusTotalConfig = {
          apiKeys: ['custom-key'],
          baseUrl: 'https://custom.api.url',
          rateLimitPerMinute: 10,
          dailyLimit: 1000,
          circuitBreakerTimeout: 600,
        };
        const customClient = new VirusTotalClient(customConfig);
        expect(customClient).toBeDefined();
      });

      it('should use default configuration from getConfig when none provided', () => {
        const defaultClient = getVirusTotalClient();
        expect(defaultClient).toBeDefined();
      });
    });

    describe('Singleton Pattern', () => {
      it('should return the same client instance on subsequent calls', () => {
        const client1 = getVirusTotalClient();
        const client2 = getVirusTotalClient();
        expect(client1).toBe(client2);
      });

      it('should allow resetting the client instance', () => {
        const client1 = getVirusTotalClient();
        resetVirusTotalClient();
        const client2 = getVirusTotalClient();
        expect(client1).not.toBe(client2);
      });

      it('should allow creating a custom client instance', () => {
        const customConfig: VirusTotalConfig = {
          apiKeys: ['custom-key'],
          baseUrl: 'https://custom.api.url',
          rateLimitPerMinute: 10,
          dailyLimit: 1000,
          circuitBreakerTimeout: 600,
        };
        const client = createVirusTotalClient(customConfig);
        expect(client).toBeDefined();
      });
    });

    describe('API Key Management', () => {
      it('should get correct API key by index', () => {
        const apiKey = (client as any).getApiKey(0);
        expect(apiKey).toBe('test-vt-key-1');
      });

      it('should throw error for invalid API key index', () => {
        expect(() => (client as any).getApiKey(10)).toThrow('Invalid API key index');
      });

      it('should handle negative index gracefully', () => {
        expect(() => (client as any).getApiKey(-1)).toThrow('Invalid API key index');
      });
    });

    describe('scan', () => {
      it('should throw error when circuit breaker blocks the request', async () => {
        // Open the circuit for API key 0
        const circuitBreaker = (client as any).circuitBreaker;
        for (let i = 0; i < 5; i++) {
          circuitBreaker.recordFailure(0, true);
        }

        await expect(client.scan('test-hash', 0)).rejects.toThrow('blocked by circuit breaker');
      });

      it('should throw rate limit error when rate limiter blocks and wait is false', async () => {
        // Consume all tokens for API key 0
        const rateLimiter = (client as any).rateLimiter;
        for (let i = 0; i < 4; i++) {
          rateLimiter.recordRequest(0);
        }

        await expect(client.scan('test-hash', 0, { wait: false })).rejects.toThrow('Rate limit exceeded');
      });

      it('should throw daily limit error when daily limit is reached', async () => {
        // Record requests up to the daily limit
        const dailyLimit = testConfig.dailyLimit;
        for (let i = 0; i < dailyLimit; i++) {
          (client as any).recordDailyRequest(0);
        }

        await expect(client.scan('test-hash', 0)).rejects.toThrow('Daily limit');
      });

      it('should make API request when all checks pass', async () => {
        const mockResponse = {
          data: {
            id: 'test-scan-id',
            type: 'analysis',
            attributes: {
              status: 'completed',
              last_analysis_stats: {
                malicious: 2,
                suspicious: 1,
                undetected: 67,
                harmless: 0,
                timeout: 0,
              },
              last_analysis_results: {
                Kaspersky: {
                  category: 'malicious',
                  engine_name: 'Kaspersky',
                  engine_version: '1.0',
                  method: 'blacklist',
                  result: 'Trojan.Generic',
                },
              },
            },
          },
        };

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse,
          status: 200,
        } as Response);

        const result = await client.scan('test-hash', 0);

        expect(result).toBeDefined();
        expect(result.scanId).toBe('test-scan-id');
        expect(result.apiKeyIndex).toBe(0);
        expect(result.positives).toBe(2);
        expect(result.total).toBeGreaterThan(0);
        expect(result.results).toBeDefined();
        expect(result.permalink).toContain('test-scan-id');
      });

      it('should handle API errors', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({ error: { code: 'invalid_api_key', message: 'Invalid API key' } }),
        } as Response);

        await expect(client.scan('test-hash', 0)).rejects.toThrow();
      });

      it('should record circuit breaker failure on rate limit error', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 429,
          json: async () => ({ error: { message: 'Rate limit exceeded' } }),
        } as Response);

        try {
          await client.scan('test-hash', 0);
        } catch {
          // Expected to fail
        }

        const circuitBreaker = (client as any).circuitBreaker;
        const state = circuitBreaker.getState(0);
        expect(state.isOpen).toBe(true);
      });
    });

    describe('getAnalysis', () => {
      it('should throw error when circuit breaker blocks the request', async () => {
        const circuitBreaker = (client as any).circuitBreaker;
        for (let i = 0; i < 5; i++) {
          circuitBreaker.recordFailure(0, true);
        }

        await expect(client.getAnalysis('test-hash', 0)).rejects.toThrow('blocked by circuit breaker');
      });

      it('should return analysis for valid hash', async () => {
        const mockResponse = {
          data: {
            id: 'test-analysis-id',
            type: 'analysis',
            attributes: {
              status: 'completed',
              last_analysis_stats: {
                malicious: 3,
                suspicious: 2,
                undetected: 65,
                harmless: 0,
                timeout: 0,
              },
              last_analysis_results: {
                Kaspersky: {
                  category: 'malicious',
                  engine_name: 'Kaspersky',
                  result: 'Trojan.Generic',
                },
              },
            },
          },
        };

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse,
          status: 200,
        } as Response);

        const result = await client.getAnalysis('test-hash', 0);

        expect(result).toBeDefined();
        expect(result.scanId).toBe('test-analysis-id');
        expect(result.positives).toBe(3);
      });
    });

    describe('Error Detection', () => {
      it('should detect rate limit errors', () => {
        const error = new Error('Rate limit exceeded - too many requests');
        const isRateLimit = (client as any).isRateLimitError(error);
        expect(isRateLimit).toBe(true);
      });

      it('should detect 429 status code in error message', () => {
        const error = new Error('HTTP 429 - Too Many Requests');
        const isRateLimit = (client as any).isRateLimitError(error);
        expect(isRateLimit).toBe(true);
      });

      it('should detect quota exceeded errors', () => {
        const error = new Error('Quota exceeded for this API key');
        const isQuotaExceeded = (client as any).isQuotaExceededError(error);
        expect(isQuotaExceeded).toBe(true);
      });

      it('should detect 402 and 403 status codes in error message', () => {
        const error402 = new Error('HTTP 402 - Payment Required');
        const error403 = new Error('HTTP 403 - Forbidden');
        expect((client as any).isQuotaExceededError(error402)).toBe(true);
        expect((client as any).isQuotaExceededError(error403)).toBe(true);
      });

      it('should return false for non-rate-limit errors', () => {
        const error = new Error('Internal server error');
        const isRateLimit = (client as any).isRateLimitError(error);
        expect(isRateLimit).toBe(false);
      });
    });

    describe('Daily Limit Management', () => {
      it('should record daily requests', () => {
        (client as any).recordDailyRequest(0);
        (client as any).recordDailyRequest(0);
        // Should not throw
      });

      it('should check daily limit correctly', () => {
        const dailyLimit = testConfig.dailyLimit;

        // Record requests up to the limit
        for (let i = 0; i < dailyLimit; i++) {
          (client as any).recordDailyRequest(0);
        }

        expect(() => (client as any).checkDailyLimit(0)).toThrow('Daily limit');
      });

      it('should allow requests under daily limit', () => {
        // Record some requests but not up to the limit
        for (let i = 0; i < 10; i++) {
          (client as any).recordDailyRequest(0);
        }

        expect(() => (client as any).checkDailyLimit(0)).not.toThrow();
      });
    });
  });

  describe('Type Tests', () => {
    it('should have VirusTotalConfig type', () => {
      const config: VirusTotalConfig = {
        apiKeys: ['key1', 'key2'],
        baseUrl: 'https://api.virustotal.com/api/v3',
        rateLimitPerMinute: 4,
        dailyLimit: 500,
        circuitBreakerTimeout: 300,
      };
      expect(config).toBeDefined();
      expect(config.apiKeys).toEqual(['key1', 'key2']);
      expect(config.rateLimitPerMinute).toBe(4);
    });

    it('should have VirusTotalResult type', () => {
      const result: VirusTotalResult = {
        scanId: 'test-scan-id',
        apiKeyIndex: 0,
        timestamp: new Date(),
        positives: 2,
        total: 70,
        results: {
          Kaspersky: {
            engine: 'Kaspersky',
            name: 'Trojan.Generic',
            category: 'malicious',
            confidence: 95,
            raw: { result: 'Trojan.Generic' },
          },
        },
        permalink: 'https://www.virustotal.com/gui/file/test-scan-id',
      };
      expect(result).toBeDefined();
      expect(result.scanId).toBe('test-scan-id');
      expect(result.positives).toBe(2);
    });

    it('should have VirusTotalAPIError type', () => {
      const error = new VirusTotalAPIError('Rate limit exceeded', 429, true, false, { apiKeyIndex: 0 });
      expect(error).toBeDefined();
      expect(error.message).toBe('Rate limit exceeded');
      expect(error.isRateLimit).toBe(true);
      expect(error.isQuotaExceeded).toBe(false);
    });
  });
});
