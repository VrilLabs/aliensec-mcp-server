import { z } from 'zod';

/**
 * AlienSec MCP Server - Core Type Definitions
 *
 * This module contains all TypeScript interfaces, types, and schemas
 * used throughout the AlienVault OTX Endpoint Security MCP Server.
 */

// ============================================================================
// Environment & Configuration Types
// ============================================================================

export interface ServerConfig {
  /** Server name for MCP identification */
  name: string;
  /** Server version */
  version: string;
  /** Debug mode flag */
  debug: boolean;
  /** Log level for the logger */
  logLevel: 'error' | 'warn' | 'info' | 'debug' | 'trace';
}

export interface AlienVaultConfig {
  /** Primary AlienVault OTX API key */
  apiKey: string;
  /** AlienVault API base URL */
  baseUrl: string;
  /** Default region for agent bootstrap */
  defaultRegion: string;
}

export interface VirusTotalConfig {
  /** Array of VirusTotal API keys (note: ToS prohibits rotation for bypassing limits) */
  apiKeys: string[];
  /** VirusTotal API base URL */
  baseUrl: string;
  /** Rate limit: requests per minute */
  rateLimitPerMinute: number;
  /** Daily limit: requests per day */
  dailyLimit: number;
  /** Circuit breaker timeout in seconds */
  circuitBreakerTimeout: number;
}

export interface DatabaseConfig {
  /** Path to the SQLite database file */
  path: string;
  /** Encryption key for the database (optional but recommended) */
  encryptionKey?: string;
  /** Database connection timeout in milliseconds */
  timeout: number;
}

export interface AppConfig {
  server: ServerConfig;
  alienVault: AlienVaultConfig;
  virusTotal: VirusTotalConfig;
  database: DatabaseConfig;
}

// ============================================================================
// Scan Types
// ============================================================================

export const ENDPOINT_FLAVORS = ['pkg', 'powershell', 'apt', 'rpm'] as const;
export const ENDPOINT_FLAVOR_SCHEMA = z.enum(ENDPOINT_FLAVORS);

export type EndpointFlavor = (typeof ENDPOINT_FLAVORS)[number];

export interface ScanRequest {
  /** Target endpoint flavor for scanning */
  flavor: EndpointFlavor;
  /** Optional target host or IP address */
  target?: string;
  /** Additional scan options */
  options?: ScanOptions;
}

export interface ScanOptions {
  /** Enable VirusTotal integration */
  useVirusTotal?: boolean;
  /** Specific API key index to use (0-based) */
  apiKeyIndex?: number;
  /** Custom osquery query to run */
  customQuery?: string;
}

export interface ScanResult {
  /** Unique scan identifier */
  scanId: string;
  /** Timestamp of the scan */
  timestamp: Date;
  /** Endpoint flavor that was scanned */
  flavor: EndpointFlavor;
  /** Target that was scanned */
  target: string;
  /** Scan status */
  status: 'success' | 'failed' | 'partial' | 'timeout';
  /** Number of threats detected */
  threatsDetected: number;
  /** Number of warnings */
  warnings: number;
  /** Detailed findings */
  findings: ScanFinding[];
  /** VirusTotal results (if enabled) */
  virusTotal?: VirusTotalResult;
  /** Raw osquery output */
  rawOutput?: string;
  /** Error message if scan failed */
  error?: string;
}

export interface ScanFinding {
  /** Finding identifier */
  id: string;
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Finding type */
  type: 'malware' | 'suspicious' | 'vulnerability' | 'policy_violation' | 'unknown';
  /** Description of the finding */
  description: string;
  /** Affected file or process */
  affected: string;
  /** Indicators of compromise */
  iocs: string[];
  /** Remediation suggestion */
  remediation?: string;
  /** Confidence score (0-100) */
  confidence: number;
  /** Source of the finding */
  source: 'alienvault' | 'virustotal' | 'custom';
}

// ============================================================================
// VirusTotal Types
// ============================================================================

export interface VirusTotalResult {
  /** VirusTotal scan ID */
  scanId: string;
  /** API key index used */
  apiKeyIndex: number;
  /** Scan timestamp */
  timestamp: Date;
  /** Number of engines that detected threats */
  positives: number;
  /** Total number of engines */
  total: number;
  /** Scan results per engine */
  results: Record<string, VirusTotalEngineResult>;
  /** Permalink to the scan */
  permalink: string;
}

export interface VirusTotalEngineResult {
  /** Engine name */
  engine: string;
  /** Detection name */
  name: string;
  /** Result category */
  category: 'malicious' | 'suspicious' | 'undetected' | 'harmless' | 'timeout' | 'error';
  /** Confidence score (0-100) */
  confidence?: number;
  /** Raw result */
  raw: unknown;
}

// ============================================================================
// Database Types
// ============================================================================

export interface DatabaseScanRecord {
  id: number;
  scanId: string;
  timestamp: string;
  flavor: EndpointFlavor;
  target: string;
  status: 'success' | 'failed' | 'partial' | 'timeout';
  threatsDetected: number;
  warnings: number;
  findingsJson: string; // JSON string of ScanFinding[]
  virusTotalJson?: string; // JSON string of VirusTotalResult
  rawOutput?: string;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export interface DatabaseCircuitBreakerRecord {
  id: number;
  apiKeyIndex: number;
  apiKeyHash: string; // SHA-256 hash of the API key for security
  eventType: 'rate_limit' | 'quota_exceeded' | 'timeout' | 'error';
  eventTimestamp: string;
  timeoutUntil: string; // When the circuit breaker will reset
  timeoutSeconds: number;
  errorMessage?: string;
  createdAt: string;
}

export interface DatabaseAPILogRecord {
  id: number;
  apiKeyIndex: number;
  apiKeyHash: string;
  requestType: 'scan' | 'lookup' | 'report' | 'other';
  requestTimestamp: string;
  responseStatus: number;
  responseTimeMs: number;
  success: boolean;
  errorMessage?: string;
  endpoint?: string;
  createdAt: string;
}

// ============================================================================
// MCP Tool Types
// ============================================================================

export interface ToolInput {
  /** Tool-specific parameters */
  [key: string]: unknown;
}

export type { CallToolResult as ToolResult } from '@modelcontextprotocol/server';

// ============================================================================
// Error Types
// ============================================================================

export class AlienSecError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode: number,
    public readonly isRetryable: boolean = false,
    public readonly context?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AlienSecError';
  }
}

export class AlienVaultAPIError extends AlienSecError {
  constructor(message: string, statusCode: number, context?: Record<string, unknown>) {
    super(message, 'ALIENVAULT_API_ERROR', statusCode, true, context);
    this.name = 'AlienVaultAPIError';
  }
}

export class VirusTotalAPIError extends AlienSecError {
  constructor(
    message: string,
    statusCode: number,
    public readonly isRateLimit: boolean = false,
    public readonly isQuotaExceeded: boolean = false,
    context?: Record<string, unknown>
  ) {
    super(message, 'VIRUSTOTAL_API_ERROR', statusCode, isRateLimit, context);
    this.name = 'VirusTotalAPIError';
    this.isRateLimit = isRateLimit;
    this.isQuotaExceeded = isQuotaExceeded;
  }
}

export class DatabaseError extends AlienSecError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'DATABASE_ERROR', 500, false, context);
    this.name = 'DatabaseError';
  }
}

export class ConfigurationError extends AlienSecError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, 'CONFIGURATION_ERROR', 400, false, context);
    this.name = 'ConfigurationError';
  }
}

// ============================================================================
// Circuit Breaker Types
// ============================================================================

export interface CircuitBreakerState {
  isOpen: boolean;
  lastFailure?: Date;
  failureCount: number;
  timeoutUntil?: Date;
  lastSuccess?: Date;
  successCount: number;
}

export interface CircuitBreakerConfig {
  /** Maximum failures before opening the circuit */
  failureThreshold: number;
  /** Reset timeout in seconds */
  resetTimeoutSeconds: number;
  /** Half-open state test count */
  halfOpenTestCount: number;
}

// ============================================================================
// Logger Types
// ============================================================================

export interface Logger {
  error(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  debug(message: string, meta?: Record<string, unknown>): void;
  trace(message: string, meta?: Record<string, unknown>): void;
  child(bindings: Record<string, unknown>): Logger;
}

// ============================================================================
// Utility Types
// ============================================================================

export type RequireAtLeastOne<T, Keys extends keyof T = keyof T> = Pick<T, Exclude<keyof T, Keys>> &
  {
    [K in Keys]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<Keys, K>>>;
  }[Keys];

export type RequireAll<T, Keys extends keyof T = keyof T> = Pick<T, Exclude<keyof T, Keys>> & Required<Pick<T, Keys>>;

export type PartialBy<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
