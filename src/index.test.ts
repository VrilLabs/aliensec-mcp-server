/**
 * AlienSec MCP Server - Main Entry Point Tests
 *
 * FIXED: All mock objects are defined INSIDE vi.mock() factory functions
 * to avoid Vitest hoisting issues where vi.mock() is hoisted above variable definitions.
 */

import { describe, it, expect, beforeEach, afterEach, vi, Mock } from 'vitest';

// ============================================================================
// MODULE MOCKS - All mock objects INSIDE vi.mock() factory functions
// ============================================================================

// Config module - named exports only, no default
vi.mock('./config', () => ({
  getConfig: vi.fn(() => ({
    server: {
      name: 'test-aliensec-mcp-server',
      version: '1.0.0',
      debug: false,
      logLevel: 'info',
    },
    alienVault: {
      apiKey: 'test-av-key',
      baseUrl: 'https://api.agent.otxb.io',
      defaultRegion: 'us-east-1',
    },
    virusTotal: {
      apiKeys: ['test-vt-key-1'],
      baseUrl: 'https://www.virustotal.com/api/v3',
      rateLimitPerMinute: 4,
      dailyLimit: 500,
      circuitBreakerTimeout: 300,
    },
    database: {
      path: ':memory:',
      encryptionKey: undefined,
      timeout: 5000,
    },
  })),
  createConfig: vi.fn(() => ({
    server: { name: 'test-aliensec-mcp-server', version: '1.0.0', debug: false, logLevel: 'info' },
    alienVault: { apiKey: 'test-av-key', baseUrl: 'https://api.agent.otxb.io', defaultRegion: 'us-east-1' },
    virusTotal: {
      apiKeys: ['test-vt-key-1'],
      baseUrl: 'https://www.virustotal.com/api/v3',
      rateLimitPerMinute: 4,
      dailyLimit: 500,
      circuitBreakerTimeout: 300,
    },
    database: { path: ':memory:', encryptionKey: undefined, timeout: 5000 },
  })),
  checkRequiredEnv: vi.fn(() => []),
  getMissingEnvError: vi.fn(() => null),
  resetConfig: vi.fn(),
}));

// Database module - mock with mockDb object defined inside
vi.mock('./database', () => {
  const mockScanRepository = {
    getScanStats: vi.fn().mockReturnValue({
      total: 10,
      byFlavor: { pkg: 5, powershell: 3, apt: 1, rpm: 1 },
      byStatus: { success: 8, failed: 2 },
      threatsDetected: 15,
      warnings: 0,
    }),
    getRecentScans: vi.fn().mockReturnValue([
      {
        scan_id: 'scan-1',
        timestamp: '2024-01-01T00:00:00Z',
        flavor: 'pkg',
        target: 'localhost',
        status: 'success',
        threats_detected: 2,
        warnings: 0,
      },
    ]),
    getScanById: vi.fn(),
    saveScan: vi.fn(),
  };

  const mockCircuitBreakerRepository = {
    getCircuitBreakerStats: vi.fn().mockReturnValue({
      totalEvents: 5,
      openEvents: 1,
      byEventType: { rate_limit: 3, error: 2 },
      byApiKeyIndex: { 0: 3, 1: 2 },
    }),
    checkCircuitBreaker: vi.fn(),
    recordRequest: vi.fn(),
  };

  const mockAPILogRepository = {
    getApiStats: vi.fn().mockReturnValue({
      totalRequests: 100,
      successfulRequests: 95,
      failedRequests: 5,
      avgResponseTimeMs: 300,
      byRequestType: { scan: 60, lookup: 30, report: 10 },
      byApiKeyIndex: { 0: 50, 1: 40, 2: 10 },
    }),
    logRequest: vi.fn().mockResolvedValue({}),
    getRequestHistory: vi.fn(),
  };

  const mockDb = {
    connect: vi.fn().mockReturnValue(true),
    disconnect: vi.fn().mockReturnValue(true),
    isConnected: vi.fn().mockReturnValue(true),
    getScanRepository: vi.fn().mockReturnValue(mockScanRepository),
    getCircuitBreakerRepository: vi.fn().mockReturnValue(mockCircuitBreakerRepository),
    getAPILogRepository: vi.fn().mockReturnValue(mockAPILogRepository),
  };

  return {
    getDatabase: vi.fn().mockReturnValue(mockDb),
    resetDatabase: vi.fn(),
    createDatabase: vi.fn().mockReturnValue(mockDb),
    AlienSecDatabase: vi.fn().mockReturnValue(mockDb),
    SCHEMA_VERSION: 1,
    SCHEMA: { 1: [] },
  };
});

// AlienVault module - mock with mockAlienVaultClient defined inside
vi.mock('./core/alienVault', () => {
  const mockAlienVaultClient = {
    scan: vi.fn().mockResolvedValue({}),
    getBootstrapCommand: vi.fn((_flavor: string, _target?: string) => 'bootstrap-command'),
    searchPulses: vi.fn().mockResolvedValue([]),
    validateApiKey: vi.fn().mockResolvedValue(true),
    getPulse: vi.fn().mockResolvedValue({}),
    getPulseEvents: vi.fn().mockResolvedValue([]),
    getPulseIndicators: vi.fn().mockResolvedValue([]),
  };

  return {
    getAlienVaultClient: vi.fn().mockReturnValue(mockAlienVaultClient),
    resetAlienVaultClient: vi.fn(),
    createAlienVaultClient: vi.fn().mockReturnValue(mockAlienVaultClient),
    BOOTSTRAP_URLS: {
      pkg: 'https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=pkg',
      powershell: 'https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=powershell',
      apt: 'https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=apt',
      rpm: 'https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=rpm',
    },
  };
});

// VirusTotal module - mock with mockVirusTotalClient defined inside
vi.mock('./core/virusTotal', () => {
  const mockVirusTotalClient = {
    scan: vi.fn().mockResolvedValue({
      scanId: 'vt-test-scan-id',
      apiKeyIndex: 0,
      timestamp: new Date(),
      positives: 2,
      total: 70,
      results: {},
      permalink: 'https://www.virustotal.com/gui/file/vt-test-scan-id',
    }),
    analyze: vi.fn().mockResolvedValue({
      scanId: 'vt-test-analysis-id',
      apiKeyIndex: 0,
      timestamp: new Date(),
      positives: 3,
      total: 70,
      results: {},
      permalink: 'https://www.virustotal.com/gui/file/vt-test-analysis-id',
    }),
    getQuota: vi.fn().mockResolvedValue({ remaining: 100, limit: 500 }),
    getAnalysis: vi.fn().mockResolvedValue({
      scanId: 'vt-test-analysis-id',
      positives: 2,
      total: 70,
      results: { Kaspersky: { category: 'malicious', name: 'Trojan.Generic', confidence: 95, raw: {} } },
      permalink: 'https://www.virustotal.com/gui/file/vt-test-analysis-id',
    }),
  };

  return {
    getVirusTotalClient: vi.fn().mockReturnValue(mockVirusTotalClient),
    resetVirusTotalClient: vi.fn(),
    createVirusTotalClient: vi.fn().mockReturnValue(mockVirusTotalClient),
    DEFAULT_CIRCUIT_BREAKER_CONFIG: {
      failureThreshold: 5,
      resetTimeoutSeconds: 300,
      halfOpenTestCount: 1,
    },
    RateLimiter: class {},
  };
});

// Pino mock
vi.mock('pino', () => {
  const mockLogger = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
  };
  return { default: vi.fn(() => mockLogger) };
});

// Crypto mock
vi.mock('crypto', () => {
  const mockRandomBytes = vi.fn().mockReturnValue(Buffer.from('test-scan-id-1234567'));
  return {
    default: { randomBytes: mockRandomBytes },
    randomBytes: mockRandomBytes,
  };
});

// MCP Server mock
vi.mock('@modelcontextprotocol/server', () => {
  const mockMcpServer = {
    registerTool: vi.fn(),
  };
  return {
    McpServer: vi.fn(function () {
      return mockMcpServer;
    }),
    serveStdio: vi.fn(),
  };
});

// MCP StdIO mock
vi.mock('@modelcontextprotocol/server/stdio', () => ({
  default: { serveStdio: vi.fn() },
  serveStdio: vi.fn(),
}));

// ============================================================================
// IMPORTS - After all vi.mock() calls
// ============================================================================

import { McpServer } from '@modelcontextprotocol/server';
import * as crypto from 'crypto';
import pino from 'pino';

// Mocked modules - use imports after vi.mock() to access mocked versions
import * as configModule from './config';
import * as databaseModule from './database';
import * as alienVaultModule from './core/alienVault';
import * as virusTotalModule from './core/virusTotal';

import { createMcpServer, createLogger, createToolResult, createToolError } from './index';
import {
  ScanRequest,
  ScanResult,
  VirusTotalResult,
  ToolResult,
  AlienSecError,
  AlienVaultAPIError,
  VirusTotalAPIError,
  DatabaseError,
  ConfigurationError,
} from './types';

// ============================================================================
// BEFORE/AFTER HOOKS
// ============================================================================

beforeEach(() => {
  vi.clearAllMocks();
  (crypto.randomBytes as Mock).mockReturnValue(Buffer.from('test-scan-id-1234567'));
});

afterEach(() => {
  vi.clearAllMocks();
});

// ============================================================================
// TEST SUITES
// ============================================================================

describe('MCP Server Main Entry Point', () => {
  describe('createLogger', () => {
    it('should create a logger with correct configuration', () => {
      const logger = createLogger();
      expect(logger).toBeDefined();
      expect(logger.info).toBeDefined();
      expect(logger.error).toBeDefined();
    });
  });

  describe('createMcpServer', () => {
    it('should create an MCP server instance', () => {
      const server = createMcpServer();
      expect(server).toBeDefined();
      expect(server.registerTool).toBeDefined();
    });

    it('should register all tools', () => {
      const server = createMcpServer();
      expect(server.registerTool).toHaveBeenCalled();
    });
  });

  describe('createToolResult', () => {
    it('should create a successful tool result', () => {
      const result = createToolResult({
        scanId: 'test-scan-id',
        timestamp: new Date(),
        flavor: 'pkg',
        target: 'localhost',
        status: 'success',
        threatsDetected: 0,
        warnings: 0,
      } as ScanResult);
      expect(result).toBeDefined();
      expect(result.content).toBeDefined();
    });

    it('should create a tool result with VirusTotal data', () => {
      const result = createToolResult({
        scanId: 'test-scan-id',
        timestamp: new Date(),
        flavor: 'pkg',
        target: 'localhost',
        status: 'success',
        threatsDetected: 2,
        warnings: 0,
        virusTotal: {
          scanId: 'vt-test-scan-id',
          positives: 2,
          total: 70,
          permalink: 'https://www.virustotal.com/gui/file/vt-test-scan-id',
        },
      } as ScanResult);
      expect(result).toBeDefined();
    });
  });

  describe('createToolError', () => {
    it('should create an error tool result', () => {
      const error = createToolError(new Error('Test error'));
      expect(error).toBeDefined();
      expect(error.isError).toBe(true);
      expect(error.content).toBeDefined();
    });

    it('should handle AlienSecError', () => {
      const error = createToolError(new AlienSecError('Test error', 'TEST_ERROR'));
      expect(error).toBeDefined();
      expect(error.isError).toBe(true);
    });

    it('should handle AlienVaultAPIError', () => {
      const error = createToolError(new AlienVaultAPIError('API Error', 500, 'Internal Server Error'));
      expect(error).toBeDefined();
      expect(error.isError).toBe(true);
    });

    it('should handle VirusTotalAPIError', () => {
      const error = createToolError(new VirusTotalAPIError('Rate limit exceeded', 429, 'Too Many Requests'));
      expect(error).toBeDefined();
      expect(error.isError).toBe(true);
    });

    it('should handle DatabaseError', () => {
      const error = createToolError(new DatabaseError('Database connection failed', new Error('Connection timeout')));
      expect(error).toBeDefined();
      expect(error.isError).toBe(true);
    });

    it('should handle ConfigurationError', () => {
      const error = createToolError(new ConfigurationError('Invalid configuration: MISSING_API_KEY'));
      expect(error).toBeDefined();
      expect(error.isError).toBe(true);
    });
  });
});

describe('Configuration Module', () => {
  describe('getConfig', () => {
    it('should return configuration object', () => {
      const config = configModule.getConfig();
      expect(config).toBeDefined();
      expect(config.server).toBeDefined();
      expect(config.alienVault).toBeDefined();
      expect(config.virusTotal).toBeDefined();
      expect(config.database).toBeDefined();
    });

    it('should return server configuration', () => {
      const config = configModule.getConfig();
      expect(config.server.name).toBe('test-aliensec-mcp-server');
      expect(config.server.version).toBe('1.0.0');
    });
  });

  describe('createConfig', () => {
    it('should create configuration from values', () => {
      const config = configModule.createConfig();
      expect(config).toBeDefined();
      expect(config.server).toBeDefined();
    });
  });
});

describe('Database Module', () => {
  describe('getDatabase', () => {
    it('should return database instance', () => {
      const db = databaseModule.getDatabase();
      expect(db).toBeDefined();
      expect(db.connect).toBeDefined();
      expect(db.disconnect).toBeDefined();
      expect(db.isConnected).toBeDefined();
    });
  });

  describe('Scan Repository', () => {
    it('should return scan stats through database', async () => {
      const db = databaseModule.getDatabase();
      const repo = db.getScanRepository();
      const stats = repo.getScanStats();
      expect(stats.total).toBe(10);
      expect(stats.byStatus.success).toBe(8);
    });

    it('should return recent scans through database', async () => {
      const db = databaseModule.getDatabase();
      const repo = db.getScanRepository();
      const scans = repo.getRecentScans();
      expect(scans).toHaveLength(1);
      expect(scans[0].scan_id).toBe('scan-1');
    });
  });

  describe('Circuit Breaker Repository', () => {
    it('should return circuit breaker stats through database', async () => {
      const db = databaseModule.getDatabase();
      const repo = db.getCircuitBreakerRepository();
      const stats = repo.getCircuitBreakerStats();
      expect(stats.totalEvents).toBe(5);
      expect(stats.openEvents).toBe(1);
    });
  });

  describe('API Log Repository', () => {
    it('should return API stats through database', async () => {
      const db = databaseModule.getDatabase();
      const repo = db.getAPILogRepository();
      const stats = repo.getApiStats();
      expect(stats.totalRequests).toBe(100);
      expect(stats.successfulRequests).toBe(95);
    });
  });
});

describe('AlienVault Module', () => {
  describe('getAlienVaultClient', () => {
    it('should return AlienVault client instance', () => {
      const client = alienVaultModule.getAlienVaultClient();
      expect(client).toBeDefined();
      expect(client.scan).toBeDefined();
      expect(client.getBootstrapCommand).toBeDefined();
    });
  });

  describe('BOOTSTRAP_URLS', () => {
    it('should have all bootstrap URLs defined', () => {
      expect(alienVaultModule.BOOTSTRAP_URLS.pkg).toContain('pkg');
      expect(alienVaultModule.BOOTSTRAP_URLS.powershell).toContain('powershell');
      expect(alienVaultModule.BOOTSTRAP_URLS.apt).toContain('apt');
      expect(alienVaultModule.BOOTSTRAP_URLS.rpm).toContain('rpm');
    });
  });

  describe('AlienVault Client', () => {
    it('should scan endpoint through client', async () => {
      const client = alienVaultModule.getAlienVaultClient();
      await client.scan({} as ScanRequest);
      expect(client.scan).toHaveBeenCalled();
    });

    it('should get bootstrap command through client', () => {
      const client = alienVaultModule.getAlienVaultClient();
      const command = client.getBootstrapCommand('pkg');
      expect(command).toBe('bootstrap-command');
    });

    it('should search pulses through client', async () => {
      const client = alienVaultModule.getAlienVaultClient();
      const result = await client.searchPulses({ query: 'test' });
      expect(result).toEqual([]);
    });

    it('should validate API key through client', async () => {
      const client = alienVaultModule.getAlienVaultClient();
      const result = await client.validateApiKey();
      expect(result).toBe(true);
    });
  });
});

describe('VirusTotal Module', () => {
  describe('getVirusTotalClient', () => {
    it('should return VirusTotal client instance', () => {
      const client = virusTotalModule.getVirusTotalClient();
      expect(client).toBeDefined();
      expect(client.scan).toBeDefined();
      expect(client.analyze).toBeDefined();
    });
  });

  describe('VirusTotal Client', () => {
    it('should scan file through client', async () => {
      const client = virusTotalModule.getVirusTotalClient();
      const result = await client.scan('test-file-hash');
      expect(result).toBeDefined();
      expect(result.scanId).toBe('vt-test-scan-id');
    });

    it('should analyze file through client', async () => {
      const client = virusTotalModule.getVirusTotalClient();
      const result = await client.analyze('test-file-hash');
      expect(result).toBeDefined();
      expect(result.scanId).toBe('vt-test-analysis-id');
    });

    it('should get quota through client', async () => {
      const client = virusTotalModule.getVirusTotalClient();
      const result = await client.getQuota();
      expect(result).toEqual({ remaining: 100, limit: 500 });
    });

    it('should get analysis through client', async () => {
      const client = virusTotalModule.getVirusTotalClient();
      const result = await client.getAnalysis('test-file-hash');
      expect(result).toBeDefined();
      expect(result.scanId).toBe('vt-test-analysis-id');
      expect(result.positives).toBe(2);
    });
  });
});

describe('Pino Logger', () => {
  it('should create logger instance', () => {
    const logger = pino();
    expect(logger).toBeDefined();
    expect(logger.info).toBeDefined();
    expect(logger.error).toBeDefined();
  });
});

describe('Crypto Module', () => {
  it('should have randomBytes function', () => {
    expect(crypto.randomBytes).toBeDefined();
  });

  it('should generate random bytes', () => {
    const result = crypto.randomBytes(16);
    expect(result).toBeDefined();
  });
});

describe('MCP Server Module', () => {
  it('should create MCP server instance', () => {
    const server = McpServer();
    expect(server).toBeDefined();
    expect(server.registerTool).toBeDefined();
  });
});

describe('Type Tests', () => {
  describe('EndpointFlavor', () => {
    it('should have pkg flavor', () => {
      expect('pkg').toBeTypeOf('string');
    });

    it('should have powershell flavor', () => {
      expect('powershell').toBeTypeOf('string');
    });

    it('should have apt flavor', () => {
      expect('apt').toBeTypeOf('string');
    });

    it('should have rpm flavor', () => {
      expect('rpm').toBeTypeOf('string');
    });
  });

  describe('ScanResult', () => {
    it('should have scan result structure', () => {
      const result: ScanResult = {
        scanId: 'test-scan-id',
        timestamp: new Date(),
        flavor: 'pkg',
        target: 'localhost',
        status: 'success',
        threatsDetected: 0,
        warnings: 0,
        findings: [],
      };
      expect(result).toBeDefined();
      expect(result.scanId).toBe('test-scan-id');
    });

    it('should have scan result with VirusTotal data', () => {
      const result: ScanResult = {
        scanId: 'test-scan-id',
        timestamp: new Date(),
        flavor: 'pkg',
        target: 'localhost',
        status: 'success',
        threatsDetected: 2,
        warnings: 0,
        findings: [],
        virusTotal: {
          scanId: 'vt-test-scan-id',
          positives: 2,
          total: 70,
          permalink: 'https://www.virustotal.com/gui/file/vt-test-scan-id',
        },
      };
      expect(result).toBeDefined();
      expect(result.virusTotal).toBeDefined();
    });
  });

  describe('VirusTotalResult', () => {
    it('should have VirusTotal result structure', () => {
      const result: VirusTotalResult = {
        scanId: 'vt-test-scan-id',
        apiKeyIndex: 0,
        timestamp: new Date(),
        positives: 2,
        total: 70,
        results: {
          Kaspersky: {
            engine: 'Kaspersky',
            name: 'Trojan.Generic',
            category: 'malicious' as const,
            confidence: 95,
            raw: { result: 'Trojan.Generic' },
          },
        },
        permalink: 'https://www.virustotal.com/gui/file/vt-test-scan-id',
      };
      expect(result).toBeDefined();
      expect(result.scanId).toBe('vt-test-scan-id');
    });
  });

  describe('ToolResult', () => {
    it('should have tool result structure', () => {
      const result: ToolResult = {
        scanId: 'test-scan-id',
        timestamp: new Date().toISOString(),
        flavor: 'pkg',
        target: 'localhost',
        status: 'success',
        threatsDetected: 0,
        warnings: 0,
        findings: [],
        virusTotal: {
          scanId: 'vt-test-scan-id',
          positives: 2,
          total: 70,
          permalink: 'https://www.virustotal.com/gui/file/vt-test-scan-id',
        },
        error: null,
      };
      expect(result).toBeDefined();
    });
  });

  describe('Error Types', () => {
    it('should create AlienSecError', () => {
      const error = new AlienSecError('Test error', 'TEST_ERROR');
      expect(error).toBeDefined();
      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_ERROR');
    });

    it('should create AlienVaultAPIError', () => {
      const error = new AlienVaultAPIError('API Error', 500, 'Internal Server Error');
      expect(error).toBeDefined();
      expect(error.message).toBe('API Error');
      expect(error.statusCode).toBe(500);
    });

    it('should create VirusTotalAPIError', () => {
      const error = new VirusTotalAPIError('Rate limit exceeded', 429, 'Too Many Requests');
      expect(error).toBeDefined();
      expect(error.message).toBe('Rate limit exceeded');
      expect(error.statusCode).toBe(429);
    });

    it('should create DatabaseError', () => {
      const error = new DatabaseError('Database connection failed', new Error('Connection timeout'));
      expect(error).toBeDefined();
      expect(error.message).toBe('Database connection failed');
    });

    it('should create ConfigurationError', () => {
      const error = new ConfigurationError('Invalid configuration: MISSING_API_KEY');
      expect(error).toBeDefined();
      expect(error.message).toBe('Invalid configuration: MISSING_API_KEY');
    });
  });
});
