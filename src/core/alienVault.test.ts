/**
 * AlienSec MCP Server - AlienVault Client Tests
 *
 * Tests for AlienVault OTX API client functionality.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock config and database modules BEFORE any imports that use them
// This is necessary due to Vitest hoisting behavior
// Note: These mocks will only affect test files that import these modules
vi.mock('../config', () => ({
  getConfig: vi.fn(),
  resetConfig: vi.fn(),
  createConfig: vi.fn(),
}));

// Mock database module - this is isolated to this test file due to Vitest's isolation mode
vi.mock('../database', () => ({
  getDatabase: vi.fn(),
  resetDatabase: vi.fn(),
  createDatabase: vi.fn(),
  AlienSecDatabase: class {},
}));

import {
  AlienVaultClient,
  getAlienVaultClient,
  resetAlienVaultClient,
  createAlienVaultClient,
  BOOTSTRAP_URLS,
} from './alienVault';
import { AlienVaultConfig, ScanRequest, EndpointFlavor } from '../types';
import { getConfig } from '../config';
import { getDatabase, resetDatabase } from '../database';
import fetch from 'node-fetch';

// Note: Global mocks are already set up in src/test/setup.ts
// for better-sqlite3-multiple-ciphers, node-fetch, and pino
// We use vi.mocked() to access the mocked implementations

// Access the globally mocked fetch
const mockFetch = vi.mocked(fetch);

describe('AlienVault Module', () => {
  let testConfig: AlienVaultConfig;

  beforeEach(() => {
    resetAlienVaultClient();
    resetDatabase();
    vi.clearAllMocks();

    // Setup test configuration
    testConfig = {
      apiKey: 'test-alienvault-api-key',
      baseUrl: 'https://api.agent.otxb.io',
      defaultRegion: 'us-east-1',
    };

    vi.mocked(getConfig).mockReturnValue({
      alienVault: testConfig,
      server: { name: 'test', version: '1.0', debug: false, logLevel: 'info' },
      virusTotal: {
        apiKeys: [],
        baseUrl: 'https://api.virustotal.com',
        rateLimitPerMinute: 4,
        dailyLimit: 500,
        circuitBreakerTimeout: 300,
      },
      database: { path: ':memory:', timeout: 5000 },
    } as any);

    // Mock database
    const mockDb = {
      getScanRepository: () => ({
        saveScanResult: vi.fn().mockResolvedValue({}),
      }),
      getCircuitBreakerRepository: () => ({}),
      getAPILogRepository: () => ({}),
    };
    vi.mocked(getDatabase).mockReturnValue(mockDb as any);
  });

  afterEach(() => {
    resetAlienVaultClient();
    resetDatabase();
    vi.restoreAllMocks();
  });

  describe('Bootstrap URLs', () => {
    it('should have bootstrap URLs for all supported flavors', () => {
      expect(BOOTSTRAP_URLS).toBeDefined();
      expect(BOOTSTRAP_URLS.pkg).toContain('bootstrap?flavor=pkg');
      expect(BOOTSTRAP_URLS.powershell).toContain('bootstrap?flavor=powershell');
      expect(BOOTSTRAP_URLS.apt).toContain('bootstrap?flavor=apt');
      expect(BOOTSTRAP_URLS.rpm).toContain('bootstrap?flavor=rpm');
    });

    it('should use the correct base URL', () => {
      Object.values(BOOTSTRAP_URLS).forEach(url => {
        expect(url).toContain('api.agent.otxb.io');
      });
    });
  });

  describe('AlienVaultClient - Bootstrap Command Generation', () => {
    let client: AlienVaultClient;

    beforeEach(() => {
      client = new AlienVaultClient(testConfig);
    });

    describe('getBootstrapCommand', () => {
      it('should generate bootstrap command for pkg flavor', () => {
        const command = client.getBootstrapCommand('pkg');
        expect(command).toContain('API_KEY=test-alienvault-api-key');
        expect(command).toContain('bootstrap?flavor=pkg');
        expect(command).toContain('bash -c');
      });

      it('should generate bootstrap command for powershell flavor', () => {
        const command = client.getBootstrapCommand('powershell');
        expect(command).toContain('API_KEY=test-alienvault-api-key');
        expect(command).toContain('bootstrap?flavor=powershell');
        expect(command).toContain('System.Net.ServicePointManager');
      });

      it('should generate bootstrap command for apt flavor', () => {
        const command = client.getBootstrapCommand('apt');
        expect(command).toContain('API_KEY=test-alienvault-api-key');
        expect(command).toContain('bootstrap?flavor=apt');
        expect(command).toContain('bash -c');
      });

      it('should generate bootstrap command for rpm flavor', () => {
        const command = client.getBootstrapCommand('rpm');
        expect(command).toContain('API_KEY=test-alienvault-api-key');
        expect(command).toContain('bootstrap?flavor=rpm');
        expect(command).toContain('bash -c');
      });

      it('should include target parameter when provided', () => {
        const command = client.getBootstrapCommand('pkg', 'test-server');
        expect(command).toContain('TARGET=test-server');
      });

      it('should throw error for unknown flavor', () => {
        expect(() => client.getBootstrapCommand('unknown' as EndpointFlavor)).toThrow(
          'Unknown endpoint flavor: unknown'
        );
      });
    });
  });

  describe('Singleton Pattern', () => {
    it('should return the same client instance on subsequent calls', () => {
      const client1 = getAlienVaultClient();
      const client2 = getAlienVaultClient();
      expect(client1).toBe(client2);
    });

    it('should allow resetting the client instance', () => {
      const client1 = getAlienVaultClient();
      resetAlienVaultClient();
      const client2 = getAlienVaultClient();
      expect(client1).not.toBe(client2);
    });

    it('should allow creating a custom client instance', () => {
      const customConfig: AlienVaultConfig = {
        apiKey: 'custom-api-key',
        baseUrl: 'https://custom.api.url',
        defaultRegion: 'us-west-1',
      };
      const client = createAlienVaultClient(customConfig);
      expect(client).toBeDefined();
      // The config is private, but we can test the bootstrap command generation
      const command = client.getBootstrapCommand('pkg');
      expect(command).toContain('API_KEY=custom-api-key');
    });
  });

  describe('Client Configuration', () => {
    it('should use provided configuration', () => {
      const customConfig: AlienVaultConfig = {
        apiKey: 'custom-key',
        baseUrl: 'https://custom.url',
        defaultRegion: 'eu-west-1',
      };
      const client = new AlienVaultClient(customConfig);
      const command = client.getBootstrapCommand('pkg');
      expect(command).toContain('API_KEY=custom-key');
    });

    it('should use default configuration from getConfig when none provided', () => {
      // This is tested by the singleton tests above
      const client = getAlienVaultClient();
      expect(client).toBeDefined();
    });
  });

  describe('Scan Functionality', () => {
    let client: AlienVaultClient;

    beforeEach(() => {
      client = new AlienVaultClient(testConfig);

      // Mock the saveScanResult method
      const mockDb = {
        getScanRepository: () => ({
          saveScanResult: vi.fn().mockReturnValue({}),
        }),
      };
      vi.mocked(getDatabase).mockReturnValue(mockDb as any);
    });

    it('should generate scan ID', async () => {
      const request: ScanRequest = {
        flavor: 'pkg',
        target: 'test-server',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      } as Response);

      const result = await client.scan(request);
      expect(result.scanId).toBeDefined();
      expect(result.scanId.length).toBe(32); // 16 bytes = 32 hex characters
    });

    it('should set correct timestamp', async () => {
      const request: ScanRequest = {
        flavor: 'pkg',
        target: 'test-server',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      } as Response);

      const beforeScan = new Date();
      const result = await client.scan(request);
      const afterScan = new Date();

      expect(result.timestamp.getTime()).toBeGreaterThanOrEqual(beforeScan.getTime());
      expect(result.timestamp.getTime()).toBeLessThanOrEqual(afterScan.getTime());
    });

    it('should use default target when not provided', async () => {
      const request: ScanRequest = {
        flavor: 'pkg',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      } as Response);

      const result = await client.scan(request);
      expect(result.target).toBe('localhost');
    });

    it('should generate findings for test/demo targets', async () => {
      const request: ScanRequest = {
        flavor: 'pkg',
        target: 'test-server',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      } as Response);

      const result = await client.scan(request);
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
      // Should have at least the informational finding
      expect(result.findings.length).toBeGreaterThan(0);
    });
  });

  describe('API Methods', () => {
    let client: AlienVaultClient;

    beforeEach(() => {
      client = new AlienVaultClient(testConfig);
    });

    describe('getPulse', () => {
      it('should fetch pulse data', async () => {
        const mockPulse = {
          id: 'pulse-123',
          name: 'Test Pulse',
          description: 'Test Description',
          reference: 'https://example.com',
          tags: ['malware', 'test'],
          created: '2024-01-01T00:00:00Z',
          modified: '2024-01-01T00:00:00Z',
        };

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockPulse,
        } as Response);

        const pulse = await client.getPulse('pulse-123');
        expect(pulse).toBeDefined();
        expect(pulse.id).toBe('pulse-123');
        expect(pulse.name).toBe('Test Pulse');
      });

      it('should throw error for invalid pulse', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 404,
          json: async () => ({ error: { message: 'Not found' } }),
        } as Response);

        await expect(client.getPulse('invalid-pulse')).rejects.toThrow();
      });
    });

    describe('searchPulses', () => {
      it('should search pulses with query', async () => {
        const mockResponse = {
          count: 1,
          pulses: [
            {
              id: 'pulse-123',
              name: 'Test Pulse',
              created: '2024-01-01T00:00:00Z',
              modified: '2024-01-01T00:00:00Z',
            },
          ],
        };

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse,
        } as Response);

        const result = await client.searchPulses('test query', 20, 0);
        expect(result).toBeDefined();
        expect(result.count).toBe(1);
        expect(result.pulses).toBeDefined();
        expect(result.pulses.length).toBe(1);
      });
    });

    describe('getPulseEvents', () => {
      it('should fetch pulse events', async () => {
        const mockEvents = [
          {
            id: 'event-123',
            pulse_id: 'pulse-123',
            title: 'Test Event',
            timestamp: '2024-01-01T00:00:00Z',
            ioc: '192.168.1.1',
            ioc_type: 'IPv4',
          },
        ];

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ events: mockEvents }),
        } as Response);

        const events = await client.getPulseEvents('pulse-123', 20, 0);
        expect(events).toBeDefined();
        expect(events.length).toBe(1);
        expect(events[0].id).toBe('event-123');
      });
    });

    describe('getPulseIndicators', () => {
      it('should fetch pulse indicators', async () => {
        const mockIndicators = [
          {
            type: 'IPv4',
            value: '192.168.1.1',
            description: 'Suspicious IP',
          },
        ];

        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ indicators: mockIndicators }),
        } as Response);

        const indicators = await client.getPulseIndicators('pulse-123');
        expect(indicators).toBeDefined();
        expect(indicators.length).toBe(1);
        expect(indicators[0].value).toBe('192.168.1.1');
      });
    });

    describe('validateApiKey', () => {
      it('should validate valid API key', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
        } as Response);

        const isValid = await client.validateApiKey();
        expect(isValid).toBe(true);
      });

      it('should return false for invalid API key', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 401,
        } as Response);

        const isValid = await client.validateApiKey();
        expect(isValid).toBe(false);
      });

      it('should handle validation errors', async () => {
        mockFetch.mockRejectedValueOnce(new Error('Network error'));

        const isValid = await client.validateApiKey();
        expect(isValid).toBe(false);
      });
    });
  });
});

describe('Type Tests', () => {
  it('should have AlienVaultConfig type', () => {
    const config: AlienVaultConfig = {
      apiKey: 'test-key',
      baseUrl: 'https://api.test.com',
      defaultRegion: 'us-east-1',
    };
    expect(config).toBeDefined();
    expect(config.apiKey).toBe('test-key');
  });

  it('should have ScanRequest type', () => {
    const request: ScanRequest = {
      flavor: 'pkg',
      target: 'test-server',
      options: {
        customQuery: 'SELECT * FROM processes',
        useVirusTotal: true,
      },
    };
    expect(request).toBeDefined();
    expect(request.flavor).toBe('pkg');
  });

  it('should have EndpointFlavor type', () => {
    const flavors: EndpointFlavor[] = ['pkg', 'powershell', 'apt', 'rpm'];
    expect(flavors).toContain('pkg');
    expect(flavors).toContain('powershell');
    expect(flavors).toContain('apt');
    expect(flavors).toContain('rpm');
  });
});
