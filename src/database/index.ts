/**
 * AlienSec MCP Server - Database Module
 *
 * SQLite database layer with optional encryption support using better-sqlite3-multiple-ciphers.
 * Provides repositories for scan records, circuit breaker events, and API logs.
 */

import Database, { Database as DatabaseType } from 'better-sqlite3-multiple-ciphers';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  DatabaseConfig,
  DatabaseScanRecord,
  DatabaseCircuitBreakerRecord,
  DatabaseAPILogRecord,
  ScanResult,
  EndpointFlavor,
  DatabaseError,
} from '../types';
import { getConfig } from '../config';

// ============================================================================
// Database Schema
// ============================================================================

const SCHEMA_VERSION = 1;

const API_KEY_HASH_SALT = 'aliensec-mcp-server:api-key-hash:v1';
const API_KEY_HASH_ITERATIONS = 120_000;
const API_KEY_HASH_KEYLEN = 32;

const SCHEMA: Record<number, string[]> = {
  1: [
    // Scan records table
    `
      CREATE TABLE IF NOT EXISTS scan_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        flavor TEXT NOT NULL CHECK(flavor IN ('pkg', 'powershell', 'apt', 'rpm')),
        target TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('success', 'failed', 'partial', 'timeout')),
        threats_detected INTEGER NOT NULL DEFAULT 0,
        warnings INTEGER NOT NULL DEFAULT 0,
        findings_json TEXT NOT NULL,
        virus_total_json TEXT,
        raw_output TEXT,
        error TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `,
    // Circuit breaker events table
    `
      CREATE TABLE IF NOT EXISTS circuit_breaker_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key_index INTEGER NOT NULL,
        api_key_hash TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK(event_type IN ('rate_limit', 'quota_exceeded', 'timeout', 'error')),
        event_timestamp TEXT NOT NULL,
        timeout_until TEXT NOT NULL,
        timeout_seconds INTEGER NOT NULL,
        error_message TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `,
    // API log table
    `
      CREATE TABLE IF NOT EXISTS api_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key_index INTEGER NOT NULL,
        api_key_hash TEXT NOT NULL,
        request_type TEXT NOT NULL CHECK(request_type IN ('scan', 'lookup', 'report', 'other')),
        request_timestamp TEXT NOT NULL,
        response_status INTEGER NOT NULL,
        response_time_ms INTEGER NOT NULL,
        success BOOLEAN NOT NULL,
        error_message TEXT,
        endpoint TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `,
    // Schema version table
    `
      CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY
      )
    `,
    // Create indexes for better query performance
    `
      CREATE INDEX IF NOT EXISTS idx_scan_records_scan_id ON scan_records(scan_id)
    `,
    `
      CREATE INDEX IF NOT EXISTS idx_scan_records_flavor ON scan_records(flavor)
    `,
    `
      CREATE INDEX IF NOT EXISTS idx_scan_records_timestamp ON scan_records(timestamp)
    `,
    `
      CREATE INDEX IF NOT EXISTS idx_scan_records_status ON scan_records(status)
    `,
    `
      CREATE INDEX IF NOT EXISTS idx_circuit_breaker_api_key ON circuit_breaker_events(api_key_index, event_type)
    `,
    `
      CREATE INDEX IF NOT EXISTS idx_circuit_breaker_timeout ON circuit_breaker_events(timeout_until)
    `,
    `
      CREATE INDEX IF NOT EXISTS idx_api_logs_api_key ON api_logs(api_key_index, request_timestamp)
    `,
    `
      CREATE INDEX IF NOT EXISTS idx_api_logs_success ON api_logs(success, request_timestamp)
    `,
  ],
};

// ============================================================================
// Database Connection
// ============================================================================

/**
 * Database connection class with encryption support.
 * Manages the SQLite database connection and provides access to repositories.
 */
export class AlienSecDatabase {
  private db: DatabaseType | null = null;
  private readonly config: DatabaseConfig;
  private readonly schemaVersion: number;

  // Repository instances (lazy-loaded)
  private scanRepository: ScanRepository | null = null;
  private circuitBreakerRepository: CircuitBreakerRepository | null = null;
  private apiLogRepository: APILogRepository | null = null;

  constructor(config: DatabaseConfig = getConfig().database) {
    this.config = config;
    this.schemaVersion = SCHEMA_VERSION;
  }

  /**
   * Opens a connection to the database.
   * Creates the database file and applies schema if needed.
   */
  connect(): DatabaseType {
    if (this.db) {
      return this.db;
    }

    // Ensure the directory exists
    const dir = path.dirname(this.config.path);
    if (dir && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    try {
      // Open database with encryption if key is provided
      const options: {
        readonly?: boolean;
        fileMustExist?: boolean;
        timeout?: number;
        key?: Buffer | string;
      } = {
        timeout: this.config.timeout,
      };

      if (this.config.encryptionKey) {
        options.key = this.config.encryptionKey;
      }

      this.db = new Database(this.config.path, options);

      // Apply schema
      this.applySchema();

      return this.db;
    } catch (error) {
      throw new DatabaseError(
        `Failed to connect to database at ${this.config.path}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Applies the database schema.
   */
  private applySchema(): void {
    if (!this.db) {
      throw new DatabaseError('Database connection not established');
    }

    // Check current schema version
    const currentVersion = this.getSchemaVersion();

    // Apply all schemas up to the current version
    for (let v = currentVersion + 1; v <= this.schemaVersion; v++) {
      const statements = SCHEMA[v];
      if (!statements) {
        throw new DatabaseError(`Schema version ${v} not found`);
      }

      for (const statement of statements) {
        this.db.exec(statement);
      }

      // Update schema version
      this.setSchemaVersion(v);
    }
  }

  /**
   * Gets the current schema version from the database.
   */
  private getSchemaVersion(): number {
    if (!this.db) {
      throw new DatabaseError('Database connection not established');
    }

    try {
      const result = this.db.prepare('SELECT version FROM schema_version LIMIT 1').get() as
        { version: number } | undefined;
      return result?.version ?? 0;
    } catch {
      return 0;
    }
  }

  /**
   * Sets the schema version in the database.
   */
  private setSchemaVersion(version: number): void {
    if (!this.db) {
      throw new DatabaseError('Database connection not established');
    }

    this.db.prepare('INSERT OR REPLACE INTO schema_version (version) VALUES (?)').run(version);
  }

  /**
   * Closes the database connection.
   */
  disconnect(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
    this.scanRepository = null;
    this.circuitBreakerRepository = null;
    this.apiLogRepository = null;
  }

  /**
   * Returns true if the database is connected.
   */
  isConnected(): boolean {
    return this.db !== null;
  }

  /**
   * Returns the raw database instance for advanced operations.
   * Use with caution.
   */
  getDatabase(): DatabaseType {
    if (!this.db) {
      throw new DatabaseError('Database connection not established');
    }
    return this.db;
  }

  /**
   * Gets the scan repository.
   */
  getScanRepository(): ScanRepository {
    if (!this.scanRepository) {
      this.scanRepository = new ScanRepository(this);
    }
    return this.scanRepository;
  }

  /**
   * Gets the circuit breaker repository.
   */
  getCircuitBreakerRepository(): CircuitBreakerRepository {
    if (!this.circuitBreakerRepository) {
      this.circuitBreakerRepository = new CircuitBreakerRepository(this);
    }
    return this.circuitBreakerRepository;
  }

  /**
   * Gets the API log repository.
   */
  getAPILogRepository(): APILogRepository {
    if (!this.apiLogRepository) {
      this.apiLogRepository = new APILogRepository(this);
    }
    return this.apiLogRepository;
  }

  /**
   * Gets the database configuration.
   */
  getConfig(): DatabaseConfig {
    return this.config;
  }
}

// ============================================================================
// Repository Base Class
// ============================================================================

/**
 * Base repository class providing common database operations.
 */
abstract class BaseRepository<T> {
  protected readonly db: AlienSecDatabase;

  constructor(db: AlienSecDatabase) {
    this.db = db;
  }

  /**
   * Gets the underlying database instance.
   */
  protected getDatabase(): DatabaseType {
    return this.db.getDatabase();
  }

  /**
   * Executes a prepared statement and returns the result.
   */
  protected exec(sql: string, params?: unknown[]): unknown {
    const db = this.getDatabase();
    return db.prepare(sql).run(params);
  }

  /**
   * Executes a prepared statement and returns the first row.
   */
  protected get(sql: string, params?: unknown[]): T | undefined {
    const db = this.getDatabase();
    return db.prepare(sql).get(params) as T | undefined;
  }

  /**
   * Executes a prepared statement and returns all rows.
   */
  protected all(sql: string, params?: unknown[]): T[] {
    const db = this.getDatabase();
    return db.prepare(sql).all(params) as T[];
  }

  /**
   * Generates a deterministic PBKDF2 hash of a string for secure storage.
   * PBKDF2 (not a fast unkeyed hash) resists brute-force lookup; the salt is
   * fixed so equal inputs (e.g. the same API key) always hash identically,
   * which is required for the `WHERE api_key_hash = ?` lookups that use it.
   */
  protected hashString(value: string): string {
    return crypto
      .pbkdf2Sync(value, API_KEY_HASH_SALT, API_KEY_HASH_ITERATIONS, API_KEY_HASH_KEYLEN, 'sha256')
      .toString('hex');
  }

  /**
   * Generates a unique ID.
   */
  protected generateId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Gets current timestamp as ISO string.
   */
  protected getTimestamp(): string {
    return new Date().toISOString();
  }
}

// ============================================================================
// Scan Repository
// ============================================================================

/**
 * Repository for managing scan records.
 */
export class ScanRepository extends BaseRepository<DatabaseScanRecord> {
  /**
   * Saves a scan result to the database.
   */
  saveScanResult(scanResult: ScanResult): DatabaseScanRecord {
    const db = this.getDatabase();

    // Serialize findings and VirusTotal result to JSON
    const findingsJson = JSON.stringify(scanResult.findings || []);
    const virusTotalJson = scanResult.virusTotal ? JSON.stringify(scanResult.virusTotal) : undefined;

    db.prepare(
      `
        INSERT INTO scan_records (
          scan_id, timestamp, flavor, target, status,
          threats_detected, warnings, findings_json, virus_total_json,
          raw_output, error, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `
    ).run(
      scanResult.scanId,
      scanResult.timestamp.toISOString(),
      scanResult.flavor,
      scanResult.target,
      scanResult.status,
      scanResult.threatsDetected,
      scanResult.warnings,
      findingsJson,
      virusTotalJson,
      scanResult.rawOutput,
      scanResult.error
    );

    return this.getScanById(scanResult.scanId)!;
  }

  /**
   * Gets a scan record by ID.
   */
  getScanById(scanId: string): DatabaseScanRecord | undefined {
    return this.get('SELECT * FROM scan_records WHERE scan_id = ?', [scanId]);
  }

  /**
   * Gets scan records by flavor.
   */
  getScansByFlavor(flavor: EndpointFlavor, limit: number = 100): DatabaseScanRecord[] {
    return this.all('SELECT * FROM scan_records WHERE flavor = ? ORDER BY timestamp DESC LIMIT ?', [flavor, limit]);
  }

  /**
   * Gets recent scan records.
   */
  getRecentScans(limit: number = 100): DatabaseScanRecord[] {
    return this.all('SELECT * FROM scan_records ORDER BY timestamp DESC LIMIT ?', [limit]);
  }

  /**
   * Gets scan records by status.
   */
  getScansByStatus(status: string, limit: number = 100): DatabaseScanRecord[] {
    return this.all('SELECT * FROM scan_records WHERE status = ? ORDER BY timestamp DESC LIMIT ?', [status, limit]);
  }

  /**
   * Gets scan statistics.
   */
  getScanStats(): {
    total: number;
    byFlavor: Record<EndpointFlavor, number>;
    byStatus: Record<string, number>;
    threatsDetected: number;
    warnings: number;
  } {
    const db = this.getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM scan_records').get() as { count: number };

    const byFlavor: Record<EndpointFlavor, number> = {
      pkg: 0,
      powershell: 0,
      apt: 0,
      rpm: 0,
    };

    const flavors = db.prepare('SELECT flavor, COUNT(*) as count FROM scan_records GROUP BY flavor').all() as Array<{
      flavor: EndpointFlavor;
      count: number;
    }>;

    for (const { flavor, count } of flavors) {
      if (flavor in byFlavor) {
        byFlavor[flavor] = count;
      }
    }

    const byStatus: Record<string, number> = {};
    const statuses = db.prepare('SELECT status, COUNT(*) as count FROM scan_records GROUP BY status').all() as Array<{
      status: string;
      count: number;
    }>;

    for (const { status, count } of statuses) {
      byStatus[status] = count;
    }

    const threats = db.prepare('SELECT SUM(threats_detected) as count FROM scan_records').get() as {
      count: number | null;
    };

    const warnings = db.prepare('SELECT SUM(warnings) as count FROM scan_records').get() as { count: number | null };

    return {
      total: total.count,
      byFlavor,
      byStatus,
      threatsDetected: threats.count ?? 0,
      warnings: warnings.count ?? 0,
    };
  }

  /**
   * Deletes scan records older than the specified date.
   */
  deleteOldScans(olderThan: Date, limit: number = 1000): number {
    const db = this.getDatabase();
    const result = db
      .prepare('DELETE FROM scan_records WHERE timestamp < ? LIMIT ?')
      .run(olderThan.toISOString(), limit);
    return result.changes || 0;
  }
}

// ============================================================================
// Circuit Breaker Repository
// ============================================================================

/**
 * Repository for managing circuit breaker events.
 */
export class CircuitBreakerRepository extends BaseRepository<DatabaseCircuitBreakerRecord> {
  /**
   * Records a circuit breaker event.
   */
  recordEvent(
    apiKeyIndex: number,
    apiKey: string,
    eventType: 'rate_limit' | 'quota_exceeded' | 'timeout' | 'error',
    timeoutSeconds: number,
    errorMessage?: string
  ): DatabaseCircuitBreakerRecord {
    const db = this.getDatabase();
    const apiKeyHash = this.hashString(apiKey);
    const now = this.getTimestamp();
    const timeoutUntil = new Date(Date.now() + timeoutSeconds * 1000).toISOString();

    const result = db
      .prepare(
        `
        INSERT INTO circuit_breaker_events (
          api_key_index, api_key_hash, event_type,
          event_timestamp, timeout_until, timeout_seconds, error_message, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `
      )
      .run(apiKeyIndex, apiKeyHash, eventType, now, timeoutUntil, timeoutSeconds, errorMessage);

    return this.getEventById(result.lastInsertRowid as number)!;
  }

  /**
   * Gets a circuit breaker event by ID.
   */
  getEventById(id: number): DatabaseCircuitBreakerRecord | undefined {
    return this.get('SELECT * FROM circuit_breaker_events WHERE id = ?', [id]);
  }

  /**
   * Gets all open circuit breaker events for a specific API key.
   */
  getOpenEvents(apiKeyIndex: number): DatabaseCircuitBreakerRecord[] {
    const now = this.getTimestamp();
    return this.all(
      `SELECT * FROM circuit_breaker_events 
       WHERE api_key_index = ? AND timeout_until > ? 
       ORDER BY event_timestamp DESC`,
      [apiKeyIndex, now]
    );
  }

  /**
   * Gets the most recent circuit breaker event for a specific API key.
   */
  getLatestEvent(apiKeyIndex: number): DatabaseCircuitBreakerRecord | undefined {
    return this.get(
      'SELECT * FROM circuit_breaker_events WHERE api_key_index = ? ORDER BY event_timestamp DESC LIMIT 1',
      [apiKeyIndex]
    );
  }

  /**
   * Checks if a specific API key is currently blocked by the circuit breaker.
   */
  isApiKeyBlocked(apiKeyIndex: number, apiKey: string): boolean {
    const apiKeyHash = this.hashString(apiKey);
    const now = this.getTimestamp();

    const result = this.get(
      `SELECT 1 FROM circuit_breaker_events 
       WHERE api_key_index = ? AND api_key_hash = ? AND timeout_until > ? 
       LIMIT 1`,
      [apiKeyIndex, apiKeyHash, now]
    );

    return result !== undefined;
  }

  /**
   * Clears expired circuit breaker events.
   */
  clearExpiredEvents(): number {
    const db = this.getDatabase();
    const now = this.getTimestamp();
    const result = db.prepare('DELETE FROM circuit_breaker_events WHERE timeout_until <= ?').run(now);
    return result.changes || 0;
  }

  /**
   * Gets circuit breaker statistics.
   */
  getCircuitBreakerStats(): {
    totalEvents: number;
    openEvents: number;
    byEventType: Record<string, number>;
    byApiKeyIndex: Record<number, number>;
  } {
    const db = this.getDatabase();
    const now = this.getTimestamp();

    const total = db.prepare('SELECT COUNT(*) as count FROM circuit_breaker_events').get() as { count: number };

    const open = db
      .prepare('SELECT COUNT(*) as count FROM circuit_breaker_events WHERE timeout_until > ?')
      .get(now) as { count: number };

    const byEventType: Record<string, number> = {};
    const eventTypes = db
      .prepare('SELECT event_type, COUNT(*) as count FROM circuit_breaker_events GROUP BY event_type')
      .all() as Array<{ event_type: string; count: number }>;

    for (const { event_type, count } of eventTypes) {
      byEventType[event_type] = count;
    }

    const byApiKeyIndex: Record<number, number> = {};
    const apiKeyIndices = db
      .prepare('SELECT api_key_index, COUNT(*) as count FROM circuit_breaker_events GROUP BY api_key_index')
      .all() as Array<{ api_key_index: number; count: number }>;

    for (const { api_key_index, count } of apiKeyIndices) {
      byApiKeyIndex[api_key_index] = count;
    }

    return {
      totalEvents: total.count,
      openEvents: open.count,
      byEventType,
      byApiKeyIndex,
    };
  }
}

// ============================================================================
// API Log Repository
// ============================================================================

/**
 * Repository for managing API log records.
 */
export class APILogRepository extends BaseRepository<DatabaseAPILogRecord> {
  /**
   * Logs an API request.
   */
  logRequest(
    apiKeyIndex: number,
    apiKey: string,
    requestType: 'scan' | 'lookup' | 'report' | 'other',
    responseStatus: number,
    responseTimeMs: number,
    success: boolean,
    errorMessage?: string,
    endpoint?: string
  ): DatabaseAPILogRecord {
    const db = this.getDatabase();
    const apiKeyHash = this.hashString(apiKey);
    const now = this.getTimestamp();

    const result = db
      .prepare(
        `
        INSERT INTO api_logs (
          api_key_index, api_key_hash, request_type,
          request_timestamp, response_status, response_time_ms,
          success, error_message, endpoint, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `
      )
      .run(apiKeyIndex, apiKeyHash, requestType, now, responseStatus, responseTimeMs, success, errorMessage, endpoint);

    return this.getLogById(result.lastInsertRowid as number)!;
  }

  /**
   * Gets an API log by ID.
   */
  getLogById(id: number): DatabaseAPILogRecord | undefined {
    return this.get('SELECT * FROM api_logs WHERE id = ?', [id]);
  }

  /**
   * Gets recent API logs for a specific API key.
   */
  getRecentLogs(apiKeyIndex: number, limit: number = 100): DatabaseAPILogRecord[] {
    return this.all('SELECT * FROM api_logs WHERE api_key_index = ? ORDER BY request_timestamp DESC LIMIT ?', [
      apiKeyIndex,
      limit,
    ]);
  }

  /**
   * Gets failed API requests.
   */
  getFailedRequests(limit: number = 100): DatabaseAPILogRecord[] {
    return this.all('SELECT * FROM api_logs WHERE success = 0 ORDER BY request_timestamp DESC LIMIT ?', [limit]);
  }

  /**
   * Gets API logs by date range.
   */
  getLogsByDateRange(startDate: Date, endDate: Date, limit: number = 1000): DatabaseAPILogRecord[] {
    return this.all(
      `SELECT * FROM api_logs 
       WHERE request_timestamp >= ? AND request_timestamp <= ? 
       ORDER BY request_timestamp DESC LIMIT ?`,
      [startDate.toISOString(), endDate.toISOString(), limit]
    );
  }

  /**
   * Gets API statistics.
   */
  getApiStats(): {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    avgResponseTimeMs: number;
    byRequestType: Record<string, number>;
    byApiKeyIndex: Record<number, number>;
  } {
    const db = this.getDatabase();

    const total = db.prepare('SELECT COUNT(*) as count FROM api_logs').get() as { count: number };

    const successful = db.prepare('SELECT COUNT(*) as count FROM api_logs WHERE success = 1').get() as {
      count: number;
    };

    const failed = db.prepare('SELECT COUNT(*) as count FROM api_logs WHERE success = 0').get() as { count: number };

    const avgResponseTime = db.prepare('SELECT AVG(response_time_ms) as avg FROM api_logs').get() as {
      avg: number | null;
    };

    const byRequestType: Record<string, number> = {};
    const requestTypes = db
      .prepare('SELECT request_type, COUNT(*) as count FROM api_logs GROUP BY request_type')
      .all() as Array<{ request_type: string; count: number }>;

    for (const { request_type, count } of requestTypes) {
      byRequestType[request_type] = count;
    }

    const byApiKeyIndex: Record<number, number> = {};
    const apiKeyIndices = db
      .prepare('SELECT api_key_index, COUNT(*) as count FROM api_logs GROUP BY api_key_index')
      .all() as Array<{ api_key_index: number; count: number }>;

    for (const { api_key_index, count } of apiKeyIndices) {
      byApiKeyIndex[api_key_index] = count;
    }

    return {
      totalRequests: total.count,
      successfulRequests: successful.count,
      failedRequests: failed.count,
      avgResponseTimeMs: Math.round(avgResponseTime.avg ?? 0),
      byRequestType,
      byApiKeyIndex,
    };
  }

  /**
   * Clears old API logs.
   */
  clearOldLogs(olderThan: Date, limit: number = 10000): number {
    const db = this.getDatabase();
    const result = db
      .prepare('DELETE FROM api_logs WHERE request_timestamp < ? LIMIT ?')
      .run(olderThan.toISOString(), limit);
    return result.changes || 0;
  }
}

// ============================================================================
// Singleton Database Instance
// ============================================================================

let databaseInstance: AlienSecDatabase | null = null;

/**
 * Gets the singleton database instance.
 */
export function getDatabase(): AlienSecDatabase {
  if (!databaseInstance) {
    databaseInstance = new AlienSecDatabase();
  }
  return databaseInstance;
}

/**
 * Resets the singleton database instance. Useful for testing.
 */
export function resetDatabase(): void {
  if (databaseInstance) {
    databaseInstance.disconnect();
    databaseInstance = null;
  }
}

/**
 * Creates a new database instance with custom configuration.
 * Useful for testing or multi-tenant scenarios.
 */
export function createDatabase(config: DatabaseConfig): AlienSecDatabase {
  return new AlienSecDatabase(config);
}

// ============================================================================
// Export
// ============================================================================

export { SCHEMA_VERSION, SCHEMA };
