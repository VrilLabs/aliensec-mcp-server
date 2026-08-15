/**
 * AlienSec MCP Server - Configuration Tests
 *
 * Tests for configuration validation, environment variable parsing, and caching.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  validateConfig,
  getConfig,
  resetConfig,
  createConfig,
  checkRequiredEnv,
  getMissingEnvError,
  serverConfigSchema,
  alienVaultConfigSchema,
  virusTotalConfigSchema,
  databaseConfigSchema,
} from './index';

describe('Configuration Module', () => {
  beforeEach(() => {
    // Reset config before each test
    resetConfig();

    // Setup test environment variables
    process.env.NAME = 'test-server';
    process.env.VERSION = '1.0.0';
    process.env.DEBUG = 'true';
    process.env.LOG_LEVEL = 'debug';
    process.env.ALIENVAULT_API_KEY = 'test-api-key';
    process.env.ALIENVAULT_BASE_URL = 'https://api.agent.otxb.io';
    process.env.ALIENVAULT_DEFAULT_REGION = 'us-west-1';
    process.env.VIRUSTOTAL_API_KEYS = 'key1,key2,key3';
    process.env.VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/api/v3';
    process.env.VIRUSTOTAL_RATE_LIMIT_PER_MINUTE = '10';
    process.env.VIRUSTOTAL_DAILY_LIMIT = '1000';
    process.env.VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT = '600';
    process.env.DATABASE_PATH = './test.db';
    process.env.DATABASE_ENCRYPTION_KEY = 'test-encryption-key';
    process.env.DATABASE_TIMEOUT = '10000';
  });

  afterEach(() => {
    // Clean up environment variables
    delete process.env.NAME;
    delete process.env.VERSION;
    delete process.env.DEBUG;
    delete process.env.LOG_LEVEL;
    delete process.env.ALIENVAULT_API_KEY;
    delete process.env.ALIENVAULT_BASE_URL;
    delete process.env.ALIENVAULT_DEFAULT_REGION;
    delete process.env.VIRUSTOTAL_API_KEYS;
    delete process.env.VIRUSTOTAL_BASE_URL;
    delete process.env.VIRUSTOTAL_RATE_LIMIT_PER_MINUTE;
    delete process.env.VIRUSTOTAL_DAILY_LIMIT;
    delete process.env.VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT;
    delete process.env.DATABASE_PATH;
    delete process.env.DATABASE_ENCRYPTION_KEY;
    delete process.env.DATABASE_TIMEOUT;

    resetConfig();
  });

  describe('validateConfig', () => {
    it('should validate and parse all environment variables correctly', () => {
      const config = validateConfig();

      expect(config.server.name).toBe('test-server');
      expect(config.server.version).toBe('1.0.0');
      expect(config.server.debug).toBe(true);
      expect(config.server.logLevel).toBe('debug');

      expect(config.alienVault.apiKey).toBe('test-api-key');
      expect(config.alienVault.baseUrl).toBe('https://api.agent.otxb.io');
      expect(config.alienVault.defaultRegion).toBe('us-west-1');

      expect(config.virusTotal.apiKeys).toEqual(['key1', 'key2', 'key3']);
      expect(config.virusTotal.baseUrl).toBe('https://www.virustotal.com/api/v3');
      expect(config.virusTotal.rateLimitPerMinute).toBe(10);
      expect(config.virusTotal.dailyLimit).toBe(1000);
      expect(config.virusTotal.circuitBreakerTimeout).toBe(600);

      expect(config.database.path).toBe('./test.db');
      expect(config.database.encryptionKey).toBe('test-encryption-key');
      expect(config.database.timeout).toBe(10000);
    });

    it('should use default values when environment variables are not set', () => {
      // Clear all environment variables
      Object.keys(process.env).forEach(key => {
        if (
          key.startsWith('NAME') ||
          key.startsWith('VERSION') ||
          key.startsWith('DEBUG') ||
          key.startsWith('LOG_LEVEL') ||
          key.startsWith('ALIENVAULT') ||
          key.startsWith('VIRUSTOTAL') ||
          key.startsWith('DATABASE')
        ) {
          delete process.env[key];
        }
      });

      // Only set required variable
      process.env.ALIENVAULT_API_KEY = 'required-key';

      const config = validateConfig();

      expect(config.server.name).toBe('aliensec-mcp-server');
      expect(config.server.version).toBe('1.0.0');
      expect(config.server.debug).toBe(false);
      expect(config.server.logLevel).toBe('info');

      expect(config.alienVault.baseUrl).toBe('https://api.agent.otxb.io');
      expect(config.alienVault.defaultRegion).toBe('us-east-1');

      expect(config.virusTotal.apiKeys).toEqual([]);
      expect(config.virusTotal.baseUrl).toBe('https://www.virustotal.com/api/v3');
      expect(config.virusTotal.rateLimitPerMinute).toBe(4);
      expect(config.virusTotal.dailyLimit).toBe(500);
      expect(config.virusTotal.circuitBreakerTimeout).toBe(300);

      expect(config.database.path).toBe('./data/aliensec.db');
      expect(config.database.encryptionKey).toBeUndefined();
      expect(config.database.timeout).toBe(5000);
    });

    it('should throw an error when required environment variables are missing', () => {
      // Clear required variable
      delete process.env.ALIENVAULT_API_KEY;

      expect(() => validateConfig()).toThrow();
    });
  });

  describe('getConfig', () => {
    it('should return cached configuration after first call', () => {
      const config1 = getConfig();
      const config2 = getConfig();

      expect(config1).toBe(config2);
      expect(config1).toBe(getConfig());
    });

    it('should validate configuration on first call', () => {
      const config = getConfig();

      expect(config.server.name).toBe('test-server');
      expect(config.alienVault.apiKey).toBe('test-api-key');
    });
  });

  describe('resetConfig', () => {
    it('should clear cached configuration', () => {
      const config1 = getConfig();
      resetConfig();
      const config2 = getConfig();

      // Config should be re-validated, not the same instance
      expect(config1).not.toBe(config2);
      // But values should be the same
      expect(config1.server.name).toBe(config2.server.name);
    });
  });

  describe('createConfig', () => {
    it('should create configuration with defaults', () => {
      const config = createConfig();

      expect(config.server.name).toBe('aliensec-mcp-server');
      expect(config.server.version).toBe('1.0.0');
      expect(config.server.debug).toBe(false);
      expect(config.server.logLevel).toBe('info');

      expect(config.alienVault.apiKey).toBe('test-api-key');
      expect(config.alienVault.baseUrl).toBe('https://api.agent.otxb.io');

      expect(config.virusTotal.apiKeys).toEqual([]);
      expect(config.virusTotal.rateLimitPerMinute).toBe(4);

      expect(config.database.path).toBe(':memory:');
      expect(config.database.timeout).toBe(5000);
    });

    it('should merge overrides with defaults', () => {
      const config = createConfig({
        server: {
          name: 'custom-server',
          debug: true,
        },
        alienVault: {
          apiKey: 'custom-key',
        },
      });

      expect(config.server.name).toBe('custom-server');
      expect(config.server.debug).toBe(true);
      expect(config.server.version).toBe('1.0.0'); // default
      expect(config.alienVault.apiKey).toBe('custom-key');
      expect(config.alienVault.baseUrl).toBe('https://api.agent.otxb.io'); // default
    });
  });

  describe('checkRequiredEnv', () => {
    it('should return empty array when all required env vars are set', () => {
      const missing = checkRequiredEnv();
      expect(missing).toEqual([]);
    });

    it('should return missing environment variables', () => {
      delete process.env.ALIENVAULT_API_KEY;

      const missing = checkRequiredEnv();
      expect(missing).toContain('ALIENVAULT_API_KEY');
    });
  });

  describe('getMissingEnvError', () => {
    it('should return empty string when no missing variables', () => {
      const error = getMissingEnvError([]);
      expect(error).toBe('');
    });

    it('should return formatted error message', () => {
      const error = getMissingEnvError(['ALIENVAULT_API_KEY', 'VIRUSTOTAL_API_KEYS']);
      expect(error).toContain('Missing required environment variables:');
      expect(error).toContain('- ALIENVAULT_API_KEY');
      expect(error).toContain('- VIRUSTOTAL_API_KEYS');
      expect(error).toContain('Please set these variables before starting the server.');
    });
  });

  describe('Schema Tests', () => {
    describe('serverConfigSchema', () => {
      it('should parse valid server config', () => {
        const env = {
          NAME: 'test',
          VERSION: '1.0',
          DEBUG: 'true',
          LOG_LEVEL: 'debug',
        };

        const result = serverConfigSchema.parse(env);
        expect(result.NAME).toBe('test');
        expect(result.DEBUG).toBe(true);
        expect(result.LOG_LEVEL).toBe('debug');
      });

      it('should use defaults for missing values', () => {
        const env = {};
        const result = serverConfigSchema.parse(env);
        expect(result.NAME).toBe('aliensec-mcp-server');
        expect(result.DEBUG).toBe(false);
        expect(result.LOG_LEVEL).toBe('info');
      });
    });

    describe('alienVaultConfigSchema', () => {
      it('should parse valid AlienVault config', () => {
        const env = {
          ALIENVAULT_API_KEY: 'test-key',
          ALIENVAULT_BASE_URL: 'https://test.url',
          ALIENVAULT_DEFAULT_REGION: 'us-west-2',
        };

        const result = alienVaultConfigSchema.parse(env);
        expect(result.ALIENVAULT_API_KEY).toBe('test-key');
        expect(result.ALIENVAULT_BASE_URL).toBe('https://test.url');
        expect(result.ALIENVAULT_DEFAULT_REGION).toBe('us-west-2');
      });

      it('should use defaults for missing values', () => {
        const env = {
          ALIENVAULT_API_KEY: 'test-key',
        };
        const result = alienVaultConfigSchema.parse(env);
        expect(result.ALIENVAULT_BASE_URL).toBe('https://api.agent.otxb.io');
        expect(result.ALIENVAULT_DEFAULT_REGION).toBe('us-east-1');
      });

      it('should throw error when API key is missing', () => {
        const env = {};
        expect(() => alienVaultConfigSchema.parse(env)).toThrow();
      });
    });

    describe('virusTotalConfigSchema', () => {
      it('should parse valid VirusTotal config with multiple API keys', () => {
        const env = {
          VIRUSTOTAL_API_KEYS: 'key1, key2, key3',
          VIRUSTOTAL_RATE_LIMIT_PER_MINUTE: '20',
          VIRUSTOTAL_DAILY_LIMIT: '2000',
          VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT: '1200',
        };

        const result = virusTotalConfigSchema.parse(env);
        expect(result.VIRUSTOTAL_API_KEYS).toEqual(['key1', 'key2', 'key3']);
        expect(result.VIRUSTOTAL_RATE_LIMIT_PER_MINUTE).toBe(20);
        expect(result.VIRUSTOTAL_DAILY_LIMIT).toBe(2000);
        expect(result.VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT).toBe(1200);
      });

      it('should handle empty API keys string', () => {
        const env = {
          VIRUSTOTAL_API_KEYS: '',
        };
        const result = virusTotalConfigSchema.parse(env);
        expect(result.VIRUSTOTAL_API_KEYS).toEqual([]);
      });

      it('should use defaults for missing values', () => {
        const env = {};
        const result = virusTotalConfigSchema.parse(env);
        expect(result.VIRUSTOTAL_API_KEYS).toEqual([]);
        expect(result.VIRUSTOTAL_RATE_LIMIT_PER_MINUTE).toBe(4);
        expect(result.VIRUSTOTAL_DAILY_LIMIT).toBe(500);
        expect(result.VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT).toBe(300);
      });
    });

    describe('databaseConfigSchema', () => {
      it('should parse valid database config', () => {
        const env = {
          DATABASE_PATH: './custom.db',
          DATABASE_ENCRYPTION_KEY: 'secret-key',
          DATABASE_TIMEOUT: '15000',
        };

        const result = databaseConfigSchema.parse(env);
        expect(result.DATABASE_PATH).toBe('./custom.db');
        expect(result.DATABASE_ENCRYPTION_KEY).toBe('secret-key');
        expect(result.DATABASE_TIMEOUT).toBe(15000);
      });

      it('should use defaults for missing values', () => {
        const env = {};
        const result = databaseConfigSchema.parse(env);
        expect(result.DATABASE_PATH).toBe('./data/aliensec.db');
        expect(result.DATABASE_ENCRYPTION_KEY).toBeUndefined();
        expect(result.DATABASE_TIMEOUT).toBe(5000);
      });
    });
  });
});
