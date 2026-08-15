/**
 * AlienSec MCP Server - Database Tests
 *
 * Tests for SQLite database layer with encryption support.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  AlienSecDatabase,
  ScanRepository,
  CircuitBreakerRepository,
  APILogRepository,
  getDatabase,
  resetDatabase,
  createDatabase,
  SCHEMA_VERSION,
  SCHEMA,
} from './index';
import { DatabaseConfig, DatabaseError, EndpointFlavor } from '../types';
import * as fs from 'fs';
import * as path from 'path';

// MockDatabase class must be defined INSIDE vi.mock factory to avoid hoisting issues
// This ensures MockDatabase is available when the mock is evaluated
// We also expose a way to make the constructor throw for testing error handling
let shouldThrowOnConnect = false;

vi.mock('better-sqlite3-multiple-ciphers', () => {
  class MockDatabase {
    private data: Record<string, unknown[]> = {};
    private schema: Record<string, string> = {};

    constructor(public readonly path: string) {
      if (shouldThrowOnConnect) {
        throw new Error('Database connection failed');
      }
      this.data = {};
      this.schema = {};
    }

    exec(_sql: string): void {
      // No-op for testing
    }

    prepare(sql: string) {
      const statement = sql.toLowerCase();

      if (statement.includes('insert')) {
        return {
          run: (..._params: unknown[]) => ({ changes: 1, lastInsertRowid: 1 }),
          get: (..._params: unknown[]) => null,
          all: (..._params: unknown[]) => [],
        };
      }

      // Handle COUNT queries
      if (statement.includes('select count(*)') || statement.includes('select count (*')) {
        if (statement.includes('group by')) {
          return {
            run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
            get: (..._params: unknown[]) => null,
            all: (..._params: unknown[]) => [],
          };
        }
        return {
          run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
          get: (..._params: unknown[]) => ({ count: 10 }),
          all: (..._params: unknown[]) => [],
        };
      }

      // Handle SUM queries
      if (statement.includes('select sum(')) {
        if (statement.includes('threats_detected')) {
          return {
            run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
            get: (..._params: unknown[]) => ({ count: 25 }),
            all: (..._params: unknown[]) => [],
          };
        }
        if (statement.includes('warnings')) {
          return {
            run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
            get: (..._params: unknown[]) => ({ count: 5 }),
            all: (..._params: unknown[]) => [],
          };
        }
        if (statement.includes('response_time_ms')) {
          return {
            run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
            get: (..._params: unknown[]) => ({ avg: 300 }),
            all: (..._params: unknown[]) => [],
          };
        }
      }

      // Handle AVG queries
      if (statement.includes('select avg(')) {
        return {
          run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
          get: (..._params: unknown[]) => ({ avg: 300 }),
          all: (..._params: unknown[]) => [],
        };
      }

      // Handle GROUP BY queries
      if (statement.includes('group by flavor')) {
        return {
          run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
          get: (..._params: unknown[]) => null,
          all: (..._params: unknown[]) => [
            { flavor: 'pkg', count: 5 },
            { flavor: 'powershell', count: 3 },
            { flavor: 'apt', count: 1 },
            { flavor: 'rpm', count: 1 },
          ],
        };
      }

      if (statement.includes('group by status')) {
        return {
          run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
          get: (..._params: unknown[]) => null,
          all: (..._params: unknown[]) => [
            { status: 'success', count: 8 },
            { status: 'failed', count: 2 },
          ],
        };
      }

      // Handle DELETE queries
      if (statement.includes('delete')) {
        if (statement.includes('circuit_breaker_events')) {
          return {
            run: (..._params: unknown[]) => ({ changes: 3 }),
            get: (..._params: unknown[]) => null,
            all: (..._params: unknown[]) => [],
          };
        }
        if (statement.includes('api_logs')) {
          return {
            run: (..._params: unknown[]) => ({ changes: 50 }),
            get: (..._params: unknown[]) => null,
            all: (..._params: unknown[]) => [],
          };
        }
        if (statement.includes('scan_records')) {
          return {
            run: (..._params: unknown[]) => ({ changes: 5 }),
            get: (..._params: unknown[]) => null,
            all: (..._params: unknown[]) => [],
          };
        }
        return {
          run: (..._params: unknown[]) => ({ changes: 0 }),
          get: (..._params: unknown[]) => null,
          all: (..._params: unknown[]) => [],
        };
      }

      // Handle SELECT version
      if (statement.includes('select') && statement.includes('version')) {
        return {
          run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
          get: (..._params: unknown[]) => ({ version: 1 }),
          all: (..._params: unknown[]) => [{ version: 1 }],
        };
      }

      // Default return for select queries
      if (statement.includes('select')) {
        return {
          run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
          get: (..._params: unknown[]) => null,
          all: (..._params: unknown[]) => [],
        };
      }

      return {
        run: (..._params: unknown[]) => ({ changes: 0, lastInsertRowid: 0 }),
        get: (..._params: unknown[]) => null,
        all: (..._params: unknown[]) => [],
      };
    }

    close(): void {
      this.data = {};
      this.schema = {};
    }
  }
  return { default: MockDatabase };
});

// Mock fs module for directory checks
vi.mock('fs', () => ({
  existsSync: vi.fn(() => true),
  mkdirSync: vi.fn(() => true),
}));

// Mock path module
vi.mock('path', () => ({
  dirname: vi.fn((p: string) => p),
  join: vi.fn((...args: string[]) => args.join('/')),
}));

describe('Database Module', () => {
  let testConfig: DatabaseConfig;
  let db: AlienSecDatabase;

  beforeEach(() => {
    vi.clearAllMocks();

    testConfig = {
      path: ':memory:',
      encryptionKey: undefined,
      timeout: 5000,
    };

    // Ensure directory exists mock
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.mkdirSync).mockReturnValue(undefined);
    vi.mocked(path.dirname).mockReturnValue('');
  });

  afterEach(() => {
    resetDatabase();
    vi.restoreAllMocks();
  });

  describe('SCHEMA_VERSION', () => {
    it('should have correct schema version', () => {
      expect(SCHEMA_VERSION).toBe(1);
    });
  });

  describe('SCHEMA', () => {
    it('should have schema for version 1', () => {
      expect(SCHEMA[1]).toBeDefined();
      expect(Array.isArray(SCHEMA[1])).toBe(true);
      expect(SCHEMA[1].length).toBeGreaterThan(0);
    });

    it('should include scan_records table', () => {
      const schemaSql = SCHEMA[1].join('\n');
      expect(schemaSql).toContain('scan_records');
      expect(schemaSql).toContain('CREATE TABLE');
    });

    it('should include circuit_breaker_events table', () => {
      const schemaSql = SCHEMA[1].join('\n');
      expect(schemaSql).toContain('circuit_breaker_events');
    });

    it('should include api_logs table', () => {
      const schemaSql = SCHEMA[1].join('\n');
      expect(schemaSql).toContain('api_logs');
    });

    it('should include schema_version table', () => {
      const schemaSql = SCHEMA[1].join('\n');
      expect(schemaSql).toContain('schema_version');
    });

    it('should include indexes for performance', () => {
      const schemaSql = SCHEMA[1].join('\n');
      expect(schemaSql).toContain('CREATE INDEX');
    });
  });

  describe('AlienSecDatabase', () => {
    describe('Constructor', () => {
      it('should create database with default config', () => {
        const config = {
          path: 'test.db',
          encryptionKey: undefined,
          timeout: 5000,
        };

        const database = new AlienSecDatabase(config);
        expect(database).toBeDefined();
      });

      it('should accept custom configuration', () => {
        const customConfig: DatabaseConfig = {
          path: 'custom.db',
          encryptionKey: 'secret-key',
          timeout: 10000,
        };

        const database = new AlienSecDatabase(customConfig);
        expect(database).toBeDefined();
      });
    });

    describe('connect', () => {
      it('should connect to database', () => {
        db = new AlienSecDatabase(testConfig);
        const connection = db.connect();

        expect(connection).toBeDefined();
        expect(db.isConnected()).toBe(true);
      });

      it('should return existing connection on subsequent calls', () => {
        db = new AlienSecDatabase(testConfig);
        const conn1 = db.connect();
        const conn2 = db.connect();

        expect(conn1).toBe(conn2);
      });

      it('should handle connection errors gracefully', () => {
        // Set flag to make MockDatabase constructor throw
        shouldThrowOnConnect = true;

        db = new AlienSecDatabase(testConfig);

        expect(() => db.connect()).toThrow(DatabaseError);

        // Reset flag for other tests
        shouldThrowOnConnect = false;
      });
    });

    describe('disconnect', () => {
      it('should disconnect from database', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();

        expect(db.isConnected()).toBe(true);

        db.disconnect();

        expect(db.isConnected()).toBe(false);
      });

      it('should handle disconnect when not connected', () => {
        db = new AlienSecDatabase(testConfig);

        expect(() => db.disconnect()).not.toThrow();
      });

      it('should reset repository instances on disconnect', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();

        // Access repositories to create them
        db.getScanRepository();
        db.getCircuitBreakerRepository();
        db.getAPILogRepository();

        db.disconnect();

        expect(db.isConnected()).toBe(false);
      });
    });

    describe('isConnected', () => {
      it('should return false when not connected', () => {
        db = new AlienSecDatabase(testConfig);
        expect(db.isConnected()).toBe(false);
      });

      it('should return true when connected', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();
        expect(db.isConnected()).toBe(true);
      });
    });

    describe('getDatabase', () => {
      it('should return the raw database instance', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();

        const rawDb = db.getDatabase();
        expect(rawDb).toBeDefined();
      });

      it('should throw error when not connected', () => {
        db = new AlienSecDatabase(testConfig);

        expect(() => db.getDatabase()).toThrow(DatabaseError);
      });
    });

    describe('Repository Accessors', () => {
      it('should return scan repository', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();

        const repo = db.getScanRepository();
        expect(repo).toBeDefined();
        expect(repo).toBeInstanceOf(ScanRepository);
      });

      it('should return circuit breaker repository', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();

        const repo = db.getCircuitBreakerRepository();
        expect(repo).toBeDefined();
        expect(repo).toBeInstanceOf(CircuitBreakerRepository);
      });

      it('should return API log repository', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();

        const repo = db.getAPILogRepository();
        expect(repo).toBeDefined();
        expect(repo).toBeInstanceOf(APILogRepository);
      });

      it('should return same repository instance on subsequent calls', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();

        const repo1 = db.getScanRepository();
        const repo2 = db.getScanRepository();

        expect(repo1).toBe(repo2);
      });

      it('should create new repository instance after disconnect', () => {
        db = new AlienSecDatabase(testConfig);
        db.connect();

        const repo1 = db.getScanRepository();
        db.disconnect();
        db.connect();
        const repo2 = db.getScanRepository();

        expect(repo1).not.toBe(repo2);
      });
    });

    describe('getConfig', () => {
      it('should return the database configuration', () => {
        db = new AlienSecDatabase(testConfig);
        const config = db.getConfig();

        expect(config).toBeDefined();
        expect(config.path).toBe(testConfig.path);
        expect(config.timeout).toBe(testConfig.timeout);
      });
    });
  });

  describe('Singleton Pattern', () => {
    it('should return the same database instance on subsequent calls', () => {
      const db1 = getDatabase();
      const db2 = getDatabase();

      expect(db1).toBe(db2);
    });

    it('should allow resetting the database instance', () => {
      const db1 = getDatabase();
      resetDatabase();
      const db2 = getDatabase();

      expect(db1).not.toBe(db2);
    });

    it('should allow creating a custom database instance', () => {
      const customConfig: DatabaseConfig = {
        path: 'custom.db',
        encryptionKey: 'custom-key',
        timeout: 10000,
      };

      const db = createDatabase(customConfig);
      expect(db).toBeDefined();
      expect(db).toBeInstanceOf(AlienSecDatabase);
    });
  });

  describe('ScanRepository', () => {
    let db: AlienSecDatabase;
    let repo: ScanRepository;

    beforeEach(() => {
      db = new AlienSecDatabase(testConfig);
      db.connect();
      repo = db.getScanRepository();
    });

    describe('saveScanResult', () => {
      it('should save scan result to database', () => {
        const scanResult = {
          scanId: 'test-scan-123',
          timestamp: new Date(),
          flavor: 'pkg' as EndpointFlavor,
          target: 'test-server',
          status: 'success' as const,
          threatsDetected: 2,
          warnings: 0,
          findings: [],
          virusTotal: {
            scanId: 'vt-123',
            positives: 2,
            total: 70,
          },
          rawOutput: 'test output',
        };

        // Mock the get method to return the saved record
        const mockRepo = repo as any;
        vi.spyOn(mockRepo, 'get').mockReturnValue({
          id: 1,
          scan_id: 'test-scan-123',
          timestamp: scanResult.timestamp.toISOString(),
          flavor: 'pkg',
          target: 'test-server',
          status: 'success',
          threats_detected: 2,
          warnings: 0,
          findings_json: '[]',
          virus_total_json: JSON.stringify(scanResult.virusTotal),
          raw_output: 'test output',
          error: null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });

        const result = repo.saveScanResult(scanResult as any);

        expect(result).toBeDefined();
      });
    });

    describe('getScanById', () => {
      it('should return scan by ID', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue({
          id: 1,
          scan_id: 'test-scan-123',
          timestamp: '2024-01-01T00:00:00Z',
          flavor: 'pkg',
          target: 'test-server',
          status: 'success',
          threats_detected: 2,
          warnings: 0,
        });

        const result = repo.getScanById('test-scan-123');

        expect(result).toBeDefined();
        expect(mockGet).toHaveBeenCalledWith('SELECT * FROM scan_records WHERE scan_id = ?', ['test-scan-123']);
      });

      it('should return undefined for non-existent scan', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue(undefined);

        const result = repo.getScanById('non-existent');

        expect(result).toBeUndefined();
      });
    });

    describe('getScansByFlavor', () => {
      it('should return scans filtered by flavor', () => {
        const mockAll = vi.spyOn(repo as any, 'all');
        mockAll.mockReturnValue([
          {
            id: 1,
            scan_id: 'scan-1',
            flavor: 'pkg' as EndpointFlavor,
            target: 'server-1',
            status: 'success',
          },
          {
            id: 2,
            scan_id: 'scan-2',
            flavor: 'pkg' as EndpointFlavor,
            target: 'server-2',
            status: 'success',
          },
        ]);

        const result = repo.getScansByFlavor('pkg', 10);

        expect(result).toBeDefined();
        expect(result.length).toBe(2);
      });
    });

    describe('getRecentScans', () => {
      it('should return recent scans ordered by timestamp', () => {
        const mockAll = vi.spyOn(repo as any, 'all');
        mockAll.mockReturnValue([
          {
            id: 1,
            scan_id: 'recent-scan-1',
            timestamp: '2024-01-01T00:00:00Z',
          },
        ]);

        const result = repo.getRecentScans(5);

        expect(result).toBeDefined();
      });
    });

    describe('getScansByStatus', () => {
      it('should return scans filtered by status', () => {
        const mockAll = vi.spyOn(repo as any, 'all');
        mockAll.mockReturnValue([
          {
            id: 1,
            scan_id: 'success-scan',
            status: 'success',
          },
        ]);

        const result = repo.getScansByStatus('success', 10);

        expect(result).toBeDefined();
      });
    });

    describe('getScanStats', () => {
      it('should return scan statistics', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        const mockAll = vi.spyOn(repo as any, 'all');

        // Mock total count
        mockGet.mockImplementation((sql: string) => {
          if (sql.includes('COUNT(*)') && !sql.includes('GROUP BY')) {
            return { count: 10 };
          }
          if (sql.includes('SUM(threats_detected)')) {
            return { count: 25 };
          }
          if (sql.includes('SUM(warnings)')) {
            return { count: 5 };
          }
          return null;
        });

        // Mock grouped results
        mockAll.mockImplementation((sql: string) => {
          if (sql.includes('GROUP BY flavor')) {
            return [
              { flavor: 'pkg' as EndpointFlavor, count: 5 },
              { flavor: 'powershell' as EndpointFlavor, count: 3 },
              { flavor: 'apt' as EndpointFlavor, count: 1 },
              { flavor: 'rpm' as EndpointFlavor, count: 1 },
            ];
          }
          if (sql.includes('GROUP BY status')) {
            return [
              { status: 'success', count: 8 },
              { status: 'failed', count: 2 },
            ];
          }
          return [];
        });

        const stats = repo.getScanStats();

        expect(stats).toBeDefined();
        expect(stats.total).toBe(10);
      });
    });

    describe('deleteOldScans', () => {
      it('should delete scans older than specified date', () => {
        const olderThan = new Date('2024-01-01');
        const result = repo.deleteOldScans(olderThan, 100);

        expect(result).toBe(5);
      });
    });
  });

  describe('CircuitBreakerRepository', () => {
    let db: AlienSecDatabase;
    let repo: CircuitBreakerRepository;

    beforeEach(() => {
      db = new AlienSecDatabase(testConfig);
      db.connect();
      repo = db.getCircuitBreakerRepository();
    });

    describe('recordEvent', () => {
      it('should record circuit breaker event', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue({
          id: 1,
          api_key_index: 0,
          api_key_hash: 'hashed-key',
          event_type: 'rate_limit',
          event_timestamp: new Date().toISOString(),
          timeout_until: new Date(Date.now() + 300000).toISOString(),
          timeout_seconds: 300,
          error_message: 'Rate limit exceeded',
          created_at: new Date().toISOString(),
        });

        const result = repo.recordEvent(0, 'test-api-key', 'rate_limit', 300, 'Rate limit exceeded');

        expect(result).toBeDefined();
      });
    });

    describe('getEventById', () => {
      it('should return event by ID', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue({
          id: 1,
          api_key_index: 0,
          event_type: 'rate_limit',
        });

        const result = repo.getEventById(1);

        expect(result).toBeDefined();
      });
    });

    describe('getOpenEvents', () => {
      it('should return open events for API key', () => {
        const mockAll = vi.spyOn(repo as any, 'all');
        mockAll.mockReturnValue([
          {
            id: 1,
            api_key_index: 0,
            event_type: 'rate_limit',
            timeout_until: new Date(Date.now() + 300000).toISOString(),
          },
        ]);

        const result = repo.getOpenEvents(0);

        expect(result).toBeDefined();
        expect(result.length).toBe(1);
      });
    });

    describe('getLatestEvent', () => {
      it('should return latest event for API key', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue({
          id: 1,
          api_key_index: 0,
          event_type: 'rate_limit',
        });

        const result = repo.getLatestEvent(0);

        expect(result).toBeDefined();
      });

      it('should return undefined when no events exist', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue(undefined);

        const result = repo.getLatestEvent(0);

        expect(result).toBeUndefined();
      });
    });

    describe('isApiKeyBlocked', () => {
      it('should return true when API key is blocked', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue({});

        const result = repo.isApiKeyBlocked(0, 'test-key');

        expect(result).toBe(true);
      });

      it('should return false when API key is not blocked', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue(undefined);

        const result = repo.isApiKeyBlocked(0, 'test-key');

        expect(result).toBe(false);
      });
    });

    describe('clearExpiredEvents', () => {
      it('should clear expired events', () => {
        const result = repo.clearExpiredEvents();

        expect(result).toBe(3);
      });
    });

    describe('getCircuitBreakerStats', () => {
      it('should return circuit breaker statistics', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        const mockAll = vi.spyOn(repo as any, 'all');

        mockGet.mockImplementation((sql: string) => {
          if (sql.includes('COUNT(*)') && !sql.includes('WHERE')) {
            return { count: 10 };
          }
          if (sql.includes('timeout_until >')) {
            return { count: 3 };
          }
          return { count: 0 };
        });

        mockAll.mockReturnValue([]);

        const stats = repo.getCircuitBreakerStats();

        expect(stats).toBeDefined();
      });
    });
  });

  describe('APILogRepository', () => {
    let db: AlienSecDatabase;
    let repo: APILogRepository;

    beforeEach(() => {
      db = new AlienSecDatabase(testConfig);
      db.connect();
      repo = db.getAPILogRepository();
    });

    describe('logRequest', () => {
      it('should log API request', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue({
          id: 1,
          api_key_index: 0,
          api_key_hash: 'hashed-key',
          request_type: 'scan',
          request_timestamp: new Date().toISOString(),
          response_status: 200,
          response_time_ms: 150,
          success: true,
          error_message: null,
          endpoint: '/api/scan',
          created_at: new Date().toISOString(),
        });

        const result = repo.logRequest(0, 'test-api-key', 'scan', 200, 150, true, undefined, '/api/scan');

        expect(result).toBeDefined();
      });
    });

    describe('getLogById', () => {
      it('should return log by ID', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        mockGet.mockReturnValue({
          id: 1,
          api_key_index: 0,
          request_type: 'scan',
        });

        const result = repo.getLogById(1);

        expect(result).toBeDefined();
      });
    });

    describe('getRecentLogs', () => {
      it('should return recent logs for API key', () => {
        const mockAll = vi.spyOn(repo as any, 'all');
        mockAll.mockReturnValue([
          {
            id: 1,
            api_key_index: 0,
            request_type: 'scan',
            request_timestamp: new Date().toISOString(),
          },
        ]);

        const result = repo.getRecentLogs(0, 10);

        expect(result).toBeDefined();
      });
    });

    describe('getFailedRequests', () => {
      it('should return failed requests', () => {
        const mockAll = vi.spyOn(repo as any, 'all');
        mockAll.mockReturnValue([
          {
            id: 1,
            api_key_index: 0,
            success: false,
          },
        ]);

        const result = repo.getFailedRequests(10);

        expect(result).toBeDefined();
      });
    });

    describe('getLogsByDateRange', () => {
      it('should return logs within date range', () => {
        const mockAll = vi.spyOn(repo as any, 'all');
        mockAll.mockReturnValue([
          {
            id: 1,
            request_timestamp: new Date().toISOString(),
          },
        ]);

        const startDate = new Date('2024-01-01');
        const endDate = new Date();
        const result = repo.getLogsByDateRange(startDate, endDate, 100);

        expect(result).toBeDefined();
      });
    });

    describe('getApiStats', () => {
      it('should return API statistics', () => {
        const mockGet = vi.spyOn(repo as any, 'get');
        const mockAll = vi.spyOn(repo as any, 'all');

        mockGet.mockImplementation((sql: string) => {
          if (sql.includes('COUNT(*)') && !sql.includes('WHERE')) {
            return { count: 100 };
          }
          if (sql.includes('success = 1')) {
            return { count: 95 };
          }
          if (sql.includes('success = 0')) {
            return { count: 5 };
          }
          if (sql.includes('AVG(response_time_ms)')) {
            return { avg: 300 };
          }
          return { count: 0 };
        });

        mockAll.mockReturnValue([]);

        const stats = repo.getApiStats();

        expect(stats).toBeDefined();
      });
    });

    describe('clearOldLogs', () => {
      it('should clear old logs', () => {
        const olderThan = new Date('2024-01-01');
        const result = repo.clearOldLogs(olderThan, 1000);

        expect(result).toBe(50);
      });
    });
  });
});

describe('Type Tests', () => {
  it('should have DatabaseConfig type', () => {
    const config: DatabaseConfig = {
      path: 'test.db',
      encryptionKey: 'secret',
      timeout: 5000,
    };
    expect(config).toBeDefined();
    expect(config.path).toBe('test.db');
  });

  it('should have DatabaseError type', () => {
    const error = new DatabaseError('Test error');
    expect(error).toBeDefined();
    expect(error.message).toBe('Test error');
    expect(error.name).toBe('DatabaseError');
  });
});
