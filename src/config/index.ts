/**
 * AlienSec MCP Server - Configuration Module
 *
 * Centralized configuration management with environment variable validation.
 * Uses Zod for runtime type validation and environment variable parsing.
 */

import { z } from 'zod';
import { AppConfig, ServerConfig, AlienVaultConfig, VirusTotalConfig, DatabaseConfig } from '../types/index.js';

// ============================================================================
// Environment Schema Definitions
// ============================================================================

const serverConfigSchema = z.object({
  NAME: z.string().default('aliensec-mcp-server'),
  VERSION: z.string().default('1.0.0'),
  DEBUG: z
    .string()
    .default('false')
    .transform(val => val.toLowerCase() === 'true'),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug', 'trace']).default('info'),
});

const alienVaultConfigSchema = z.object({
  ALIENVAULT_API_KEY: z.string().min(1, 'ALIENVAULT_API_KEY is required'),
  ALIENVAULT_BASE_URL: z.string().url().default('https://api.agent.otxb.io'),
  ALIENVAULT_DEFAULT_REGION: z.string().default('us-east-1'),
});

const virusTotalConfigSchema = z.object({
  VIRUSTOTAL_API_KEYS: z
    .string()
    .default('')
    .transform(val => {
      // Parse comma-separated API keys
      if (!val.trim()) return [] as string[];
      return val
        .split(',')
        .map(key => key.trim())
        .filter(Boolean);
    }),
  VIRUSTOTAL_BASE_URL: z.string().url().default('https://www.virustotal.com/api/v3'),
  VIRUSTOTAL_RATE_LIMIT_PER_MINUTE: z.string().default('4').transform(Number),
  VIRUSTOTAL_DAILY_LIMIT: z.string().default('500').transform(Number),
  VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT: z.string().default('300').transform(Number), // 5 minutes in seconds
});

const databaseConfigSchema = z.object({
  DATABASE_PATH: z.string().default('./data/aliensec.db'),
  DATABASE_ENCRYPTION_KEY: z.string().optional(),
  DATABASE_TIMEOUT: z.string().default('5000').transform(Number), // 5 seconds in milliseconds
});

// ============================================================================
// Configuration Validation
// ============================================================================

/**
 * Validates environment variables and returns a strongly-typed configuration object.
 * Throws an error if required environment variables are missing.
 */
export function validateConfig(): AppConfig {
  // Parse and validate server configuration
  const serverEnv = serverConfigSchema.parse(process.env);
  const serverConfig: ServerConfig = {
    name: serverEnv.NAME,
    version: serverEnv.VERSION,
    debug: serverEnv.DEBUG,
    logLevel: serverEnv.LOG_LEVEL,
  };

  // Parse and validate AlienVault configuration
  const alienVaultEnv = alienVaultConfigSchema.parse(process.env);
  const alienVaultConfig: AlienVaultConfig = {
    apiKey: alienVaultEnv.ALIENVAULT_API_KEY,
    baseUrl: alienVaultEnv.ALIENVAULT_BASE_URL,
    defaultRegion: alienVaultEnv.ALIENVAULT_DEFAULT_REGION,
  };

  // Parse and validate VirusTotal configuration
  const virusTotalEnv = virusTotalConfigSchema.parse(process.env);
  const virusTotalConfig: VirusTotalConfig = {
    apiKeys: virusTotalEnv.VIRUSTOTAL_API_KEYS,
    baseUrl: virusTotalEnv.VIRUSTOTAL_BASE_URL,
    rateLimitPerMinute: virusTotalEnv.VIRUSTOTAL_RATE_LIMIT_PER_MINUTE,
    dailyLimit: virusTotalEnv.VIRUSTOTAL_DAILY_LIMIT,
    circuitBreakerTimeout: virusTotalEnv.VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT,
  };

  // Parse and validate database configuration
  const databaseEnv = databaseConfigSchema.parse(process.env);
  const databaseConfig: DatabaseConfig = {
    path: databaseEnv.DATABASE_PATH,
    encryptionKey: databaseEnv.DATABASE_ENCRYPTION_KEY,
    timeout: databaseEnv.DATABASE_TIMEOUT,
  };

  return {
    server: serverConfig,
    alienVault: alienVaultConfig,
    virusTotal: virusTotalConfig,
    database: databaseConfig,
  };
}

/**
 * Returns the current configuration. Caches the configuration after first validation.
 */
let cachedConfig: AppConfig | null = null;

export function getConfig(): AppConfig {
  if (cachedConfig) {
    return cachedConfig;
  }

  cachedConfig = validateConfig();
  return cachedConfig;
}

/**
 * Resets the cached configuration. Useful for testing.
 */
export function resetConfig(): void {
  cachedConfig = null;
}

/**
 * Creates a configuration object from explicit values (useful for testing).
 */
export function createConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const defaultConfig: AppConfig = {
    server: {
      name: 'aliensec-mcp-server',
      version: '1.0.0',
      debug: false,
      logLevel: 'info',
    },
    alienVault: {
      apiKey: 'test-api-key',
      baseUrl: 'https://api.agent.otxb.io',
      defaultRegion: 'us-east-1',
    },
    virusTotal: {
      apiKeys: [],
      baseUrl: 'https://www.virustotal.com/api/v3',
      rateLimitPerMinute: 4,
      dailyLimit: 500,
      circuitBreakerTimeout: 300,
    },
    database: {
      path: ':memory:',
      timeout: 5000,
    },
  };

  return {
    ...defaultConfig,
    ...overrides,
    server: { ...defaultConfig.server, ...overrides.server },
    alienVault: { ...defaultConfig.alienVault, ...overrides.alienVault },
    virusTotal: { ...defaultConfig.virusTotal, ...overrides.virusTotal },
    database: { ...defaultConfig.database, ...overrides.database },
  };
}

// ============================================================================
// Configuration Validation Helpers
// ============================================================================

/**
 * Validates that required environment variables are present.
 * Returns a list of missing environment variable names.
 */
export function checkRequiredEnv(): string[] {
  const required = ['ALIENVAULT_API_KEY'] as const;

  const missing: string[] = [];

  for (const key of required) {
    if (!process.env[key]) {
      missing.push(key);
    }
  }

  return missing;
}

/**
 * Generates a user-friendly error message for missing environment variables.
 */
export function getMissingEnvError(missing: string[]): string {
  if (missing.length === 0) return '';

  const message = [
    'Missing required environment variables:',
    ...missing.map(key => `  - ${key}`),
    '',
    'Please set these variables before starting the server.',
  ].join('\n');

  return message;
}

// ============================================================================
// Export
// ============================================================================

export { serverConfigSchema, alienVaultConfigSchema, virusTotalConfigSchema, databaseConfigSchema };
