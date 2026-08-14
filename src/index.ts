/**
 * AlienSec MCP Server - Main Entry Point
 * 
 * This is the production-ready MCP (Model Context Protocol) server for AlienVault OTX
 * Endpoint Security Scanning with VirusTotal Integration.
 * 
 * Features:
 * - Scan macOS PKG Installer endpoints
 * - Scan Windows endpoints via PowerShell
 * - Scan Debian/APT endpoints
 * - Scan Redhat/RPM endpoints
 * - VirusTotal API integration with rate limiting and circuit breaker
 * - SQLite database with optional encryption for data persistence
 * - Comprehensive error handling and logging
 * - Production-grade code quality and best practices
 */

import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import * as crypto from 'crypto';
import pino from 'pino';
import {
  getConfig,
  createConfig,
  checkRequiredEnv,
  getMissingEnvError,
} from './config';
import {
  getDatabase,
  resetDatabase,
  AlienSecDatabase,
} from './database';
import {
  getAlienVaultClient,
  resetAlienVaultClient,
  BOOTSTRAP_URLS,
} from './core/alienVault';
import {
  getVirusTotalClient,
  resetVirusTotalClient,
} from './core/virusTotal';
import {
  EndpointFlavor,
  ScanRequest,
  ScanResult,
  VirusTotalResult,
  ToolResult,
  AlienSecError,
} from './types';

// ============================================================================
// Server Configuration
// ============================================================================

const SERVER_NAME = 'aliensec-mcp-server';
const SERVER_VERSION = '1.0.0';

// ============================================================================
// Logger Setup
// ============================================================================

function createLogger() {
  const config = getConfig();
  
  return pino({
    level: config.server.logLevel,
    name: SERVER_NAME,
    timestamp: () => new Date().toISOString(),
    messageKey: 'message',
    formatters: {
      level: (label) => ({ level: label.toUpperCase() }),
      log: (object) => {
        // Redact sensitive information
        const { apiKey, ...rest } = object;
        return rest;
      },
    },
  });
}

// ============================================================================
// MCP Server Factory
// ============================================================================

/**
 * Creates and configures the MCP server with all tools.
 */
function createMcpServer(): McpServer {
  const config = getConfig();
  const logger = createLogger();

  // Initialize database connection
  const database = getDatabase();
  try {
    database.connect();
    logger.info('Database connection established');
  } catch (error) {
    logger.error('Failed to connect to database', { error });
    throw error;
  }

  // Create the MCP server
  const server = new McpServer({
    name: config.server.name || SERVER_NAME,
    version: config.server.version || SERVER_VERSION,
    description: 'AlienVault OTX Endpoint Security Scanning MCP Server with VirusTotal Integration',
    capabilities: {
      tools: {},
      resources: {},
      prompts: {},
    },
  });

  // ======================================================================
  // Register Scan Tools
  // ======================================================================

  /**
   * Generic scan tool that handles all endpoint flavors.
   */
  server.registerTool(
    'scan_endpoint',
    {
      title: 'Scan Endpoint with AlienVault OTX',
      description: 'Scan an endpoint using AlienVault OTX agent. Supports macOS PKG, Windows PowerShell, Debian APT, and Redhat RPM endpoints.',
      inputSchema: z.object({
        flavor: z
          .enum(['pkg', 'powershell', 'apt', 'rpm'] as const)
          .describe('Endpoint flavor to scan: pkg (macOS), powershell (Windows), apt (Debian), rpm (Redhat)'),
        target: z
          .string()
          .optional()
          .describe('Target hostname or IP address to scan'),
        useVirusTotal: z
          .boolean()
          .optional()
          .default(false)
          .describe('Enable VirusTotal integration for additional threat intelligence'),
        apiKeyIndex: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .default(0)
          .describe('VirusTotal API key index to use (0-based)'),
      }),
    },
    async ({ flavor, target, useVirusTotal, apiKeyIndex }) => {
      const scanId = crypto.randomBytes(16).toString('hex');
      const timestamp = new Date();
      const actualTarget = target || 'localhost';

      try {
        logger.info('Starting endpoint scan', { scanId, flavor, target: actualTarget });

        const alienVaultClient = getAlienVaultClient();
        const scanRequest: ScanRequest = {
          flavor,
          target: actualTarget,
          options: {
            useVirusTotal,
            apiKeyIndex,
          },
        };

        const result = await alienVaultClient.scan(scanRequest);

        logger.info('Endpoint scan completed', {
          scanId,
          flavor,
          target: actualTarget,
          status: result.status,
          threatsDetected: result.threatsDetected,
          warnings: result.warnings,
        });

        // Format the response
        return createToolResult(
          `Scan ${scanId} completed successfully for ${actualTarget} (${flavor})`,
          {
            scanId: result.scanId,
            timestamp: result.timestamp.toISOString(),
            flavor: result.flavor,
            target: result.target,
            status: result.status,
            threatsDetected: result.threatsDetected,
            warnings: result.warnings,
            findings: result.findings.map((f) => ({
              id: f.id,
              severity: f.severity,
              type: f.type,
              description: f.description,
              affected: f.affected,
              iocs: f.iocs,
              confidence: f.confidence,
              source: f.source,
            })),
            virusTotal: result.virusTotal ? {
              scanId: result.virusTotal.scanId,
              positives: result.virusTotal.positives,
              total: result.virusTotal.total,
              permalink: result.virusTotal.permalink,
            } : undefined,
          }
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error('Endpoint scan failed', { scanId, flavor, target: actualTarget, error: errorMessage });

        return createToolError(
          `Scan failed: ${errorMessage}`,
          { scanId, flavor, target: actualTarget, error: errorMessage }
        );
      }
    }
  );

  /**
   * Scan macOS PKG Installer endpoints.
   */
  server.registerTool(
    'scan_macos_pkg',
    {
      title: 'Scan macOS PKG Installer',
      description: 'Scan a macOS system using the PKG installer flavor of AlienVault OTX agent.',
      inputSchema: z.object({
        target: z
          .string()
          .optional()
          .describe('Target macOS hostname or IP address'),
        useVirusTotal: z
          .boolean()
          .optional()
          .default(false)
          .describe('Enable VirusTotal integration'),
      }),
    },
    async ({ target, useVirusTotal }) => {
      return server.invokeTool('scan_endpoint', {
        flavor: 'pkg',
        target,
        useVirusTotal,
      });
    }
  );

  /**
   * Scan Windows endpoints.
   */
  server.registerTool(
    'scan_windows',
    {
      title: 'Scan Windows Endpoint',
      description: 'Scan a Windows system using the PowerShell flavor of AlienVault OTX agent.',
      inputSchema: z.object({
        target: z
          .string()
          .optional()
          .describe('Target Windows hostname or IP address'),
        useVirusTotal: z
          .boolean()
          .optional()
          .default(false)
          .describe('Enable VirusTotal integration'),
      }),
    },
    async ({ target, useVirusTotal }) => {
      return server.invokeTool('scan_endpoint', {
        flavor: 'powershell',
        target,
        useVirusTotal,
      });
    }
  );

  /**
   * Scan Debian/APT endpoints.
   */
  server.registerTool(
    'scan_debian_apt',
    {
      title: 'Scan Debian/APT Endpoint',
      description: 'Scan a Debian/Ubuntu system using the APT flavor of AlienVault OTX agent.',
      inputSchema: z.object({
        target: z
          .string()
          .optional()
          .describe('Target Debian/Ubuntu hostname or IP address'),
        useVirusTotal: z
          .boolean()
          .optional()
          .default(false)
          .describe('Enable VirusTotal integration'),
      }),
    },
    async ({ target, useVirusTotal }) => {
      return server.invokeTool('scan_endpoint', {
        flavor: 'apt',
        target,
        useVirusTotal,
      });
    }
  );

  /**
   * Scan Redhat/RPM endpoints.
   */
  server.registerTool(
    'scan_redhat_rpm',
    {
      title: 'Scan Redhat/RPM Endpoint',
      description: 'Scan a Redhat/CentOS system using the RPM flavor of AlienVault OTX agent.',
      inputSchema: z.object({
        target: z
          .string()
          .optional()
          .describe('Target Redhat/CentOS hostname or IP address'),
        useVirusTotal: z
          .boolean()
          .optional()
          .default(false)
          .describe('Enable VirusTotal integration'),
      }),
    },
    async ({ target, useVirusTotal }) => {
      return server.invokeTool('scan_endpoint', {
        flavor: 'rpm',
        target,
        useVirusTotal,
      });
    }
  );

  // ======================================================================
  // Register VirusTotal Tools
  // ======================================================================

  /**
   * Use VirusTotal to scan a file hash or URL.
   */
  server.registerTool(
    'use_virustotal',
    {
      title: 'Scan with VirusTotal',
      description: 'Scan a file hash or URL using VirusTotal API. Note: Respects VirusTotal ToS - multiple API keys are for redundancy, not for bypassing rate limits.',
      inputSchema: z.object({
        resource: z
          .string()
          .describe('File hash (SHA-256, MD5, SHA-1) or URL to scan'),
        apiKeyIndex: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .default(0)
          .describe('VirusTotal API key index to use (0-based)'),
        wait: z
          .boolean()
          .optional()
          .default(true)
          .describe('Whether to wait if rate limited (default: true)'),
      }),
    },
    async ({ resource, apiKeyIndex, wait }) => {
      const scanId = crypto.randomBytes(16).toString('hex');

      try {
        logger.info('Starting VirusTotal scan', { scanId, resource, keySlot: apiKeyIndex });

        const virusTotalClient = getVirusTotalClient();
        const result = await virusTotalClient.scan(resource, apiKeyIndex, { wait });

        logger.info('VirusTotal scan completed', {
          scanId,
          resource,
          positives: result.positives,
          total: result.total,
        });

        return createToolResult(
          `VirusTotal scan ${result.scanId} completed: ${result.positives}/${result.total} engines detected threats`,
          {
            scanId: result.scanId,
            timestamp: result.timestamp.toISOString(),
            positives: result.positives,
            total: result.total,
            results: Object.entries(result.results).map(([engine, r]) => ({
              engine,
              category: r.category,
              name: r.name,
              confidence: r.confidence,
            })),
            permalink: result.permalink,
          }
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error('VirusTotal scan failed', { scanId, resource, keySlot: apiKeyIndex, error: errorMessage });

        return createToolError(
          `VirusTotal scan failed: ${errorMessage}`,
          { scanId, resource, apiKeyIndex, error: errorMessage }
        );
      }
    }
  );

  /**
   * Get VirusTotal analysis for a file hash.
   */
  server.registerTool(
    'get_virustotal_analysis',
    {
      title: 'Get VirusTotal Analysis',
      description: 'Get existing analysis results for a file hash from VirusTotal.',
      inputSchema: z.object({
        hash: z
          .string()
          .describe('File hash to get analysis for'),
        apiKeyIndex: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .default(0)
          .describe('VirusTotal API key index to use'),
      }),
    },
    async ({ hash, apiKeyIndex }) => {
      const requestId = crypto.randomBytes(16).toString('hex');

      try {
        logger.info('Getting VirusTotal analysis', { requestId, hash, keySlot: apiKeyIndex });

        const virusTotalClient = getVirusTotalClient();
        const result = await virusTotalClient.getAnalysis(hash, apiKeyIndex);

        return createToolResult(
          `VirusTotal analysis for ${hash}: ${result.positives}/${result.total} engines detected threats`,
          {
            scanId: result.scanId,
            positives: result.positives,
            total: result.total,
            results: Object.entries(result.results).map(([engine, r]) => ({
              engine,
              category: r.category,
              name: r.name,
            })),
            permalink: result.permalink,
          }
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error('Failed to get VirusTotal analysis', { requestId, hash, keySlot: apiKeyIndex, error: errorMessage });

        return createToolError(
          `Failed to get VirusTotal analysis: ${errorMessage}`,
          { requestId, hash, apiKeyIndex, error: errorMessage }
        );
      }
    }
  );

  // ======================================================================
  // Register AlienVault OTX Tools
  // ======================================================================

  /**
   * Get AlienVault OTX bootstrap command for a specific flavor.
   */
  server.registerTool(
    'get_bootstrap_command',
    {
      title: 'Get AlienVault OTX Bootstrap Command',
      description: 'Get the bootstrap command for installing the AlienVault OTX agent on a specific endpoint flavor.',
      inputSchema: z.object({
        flavor: z
          .enum(['pkg', 'powershell', 'apt', 'rpm'] as const)
          .describe('Endpoint flavor: pkg (macOS), powershell (Windows), apt (Debian), rpm (Redhat)'),
        target: z
          .string()
          .optional()
          .describe('Optional target hostname for the bootstrap command'),
      }),
    },
    async ({ flavor, target }) => {
      try {
        const alienVaultClient = getAlienVaultClient();
        const command = alienVaultClient.getBootstrapCommand(flavor, target);

        return createToolResult(
          `Bootstrap command for ${flavor} flavor`,
          {
            flavor,
            target: target || 'localhost',
            command,
            url: BOOTSTRAP_URLS[flavor],
          }
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return createToolError(
          `Failed to generate bootstrap command: ${errorMessage}`,
          { flavor, target, error: errorMessage }
        );
      }
    }
  );

  /**
   * Get all bootstrap URLs.
   */
  server.registerTool(
    'get_bootstrap_urls',
    {
      title: 'Get All Bootstrap URLs',
      description: 'Get all available AlienVault OTX bootstrap URLs for different endpoint flavors.',
      inputSchema: z.object({}),
    },
    async () => {
      return createToolResult(
        'AlienVault OTX Bootstrap URLs',
        BOOTSTRAP_URLS
      );
    }
  );

  /**
   * Search AlienVault OTX pulses.
   */
  server.registerTool(
    'search_pulses',
    {
      title: 'Search AlienVault OTX Pulses',
      description: 'Search for threat intelligence pulses in AlienVault OTX.',
      inputSchema: z.object({
        query: z
          .string()
          .describe('Search query for pulses'),
        limit: z
          .number()
          .int()
          .positive()
          .optional()
          .default(20)
          .describe('Maximum number of results to return'),
        offset: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .default(0)
          .describe('Offset for pagination'),
      }),
    },
    async ({ query, limit, offset }) => {
      const requestId = crypto.randomBytes(16).toString('hex');

      try {
        logger.info('Searching AlienVault OTX pulses', { requestId, query, limit, offset });

        const alienVaultClient = getAlienVaultClient();
        const result = await alienVaultClient.searchPulses(query, limit, offset);

        return createToolResult(
          `Found ${result.count} pulses matching "${query}"`,
          {
            count: result.count,
            pulses: result.pulses.map((p) => ({
              id: p.id,
              name: p.name,
              description: p.description,
              author: p.author,
              created: p.created,
              modified: p.modified,
              tags: p.tags,
            })),
          }
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error('Failed to search pulses', { requestId, query, limit, offset, error: errorMessage });

        return createToolError(
          `Failed to search pulses: ${errorMessage}`,
          { requestId, query, limit, offset, error: errorMessage }
        );
      }
    }
  );

  // ======================================================================
  // Register Database Query Tools
  // ======================================================================

  /**
   * Get scan statistics from the database.
   */
  server.registerTool(
    'get_scan_stats',
    {
      title: 'Get Scan Statistics',
      description: 'Get statistics about all scans stored in the database.',
      inputSchema: z.object({}),
    },
    async () => {
      try {
        const db = getDatabase();
        const repo = db.getScanRepository();
        const stats = repo.getScanStats();

        return createToolResult(
          'Scan Statistics',
          stats
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return createToolError(
          `Failed to get scan statistics: ${errorMessage}`,
          { error: errorMessage }
        );
      }
    }
  );

  /**
   * Get recent scans from the database.
   */
  server.registerTool(
    'get_recent_scans',
    {
      title: 'Get Recent Scans',
      description: 'Get a list of recent scans from the database.',
      inputSchema: z.object({
        limit: z
          .number()
          .int()
          .positive()
          .optional()
          .default(10)
          .describe('Maximum number of scans to return'),
      }),
    },
    async ({ limit }) => {
      try {
        const db = getDatabase();
        const repo = db.getScanRepository();
        const scans = repo.getRecentScans(limit);

        return createToolResult(
          `Recent Scans (last ${limit})`,
          scans.map((s) => ({
            scanId: s.scan_id,
            timestamp: s.timestamp,
            flavor: s.flavor,
            target: s.target,
            status: s.status,
            threatsDetected: s.threats_detected,
            warnings: s.warnings,
          }))
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return createToolError(
          `Failed to get recent scans: ${errorMessage}`,
          { limit, error: errorMessage }
        );
      }
    }
  );

  /**
   * Get circuit breaker statistics.
   */
  server.registerTool(
    'get_circuit_breaker_stats',
    {
      title: 'Get Circuit Breaker Statistics',
      description: 'Get statistics about circuit breaker events for VirusTotal API keys.',
      inputSchema: z.object({}),
    },
    async () => {
      try {
        const db = getDatabase();
        const repo = db.getCircuitBreakerRepository();
        const stats = repo.getCircuitBreakerStats();

        return createToolResult(
          'Circuit Breaker Statistics',
          stats
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return createToolError(
          `Failed to get circuit breaker statistics: ${errorMessage}`,
          { error: errorMessage }
        );
      }
    }
  );

  /**
   * Get API log statistics.
   */
  server.registerTool(
    'get_api_stats',
    {
      title: 'Get API Statistics',
      description: 'Get statistics about VirusTotal API requests.',
      inputSchema: z.object({}),
    },
    async () => {
      try {
        const db = getDatabase();
        const repo = db.getAPILogRepository();
        const stats = repo.getApiStats();

        return createToolResult(
          'API Statistics',
          stats
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return createToolError(
          `Failed to get API statistics: ${errorMessage}`,
          { error: errorMessage }
        );
      }
    }
  );

  // ======================================================================
  // Register System Tools
  // ======================================================================

  /**
   * Get server health and status.
   */
  server.registerTool(
    'get_health',
    {
      title: 'Get Server Health',
      description: 'Get the health status of the AlienSec MCP server.',
      inputSchema: z.object({}),
    },
    async () => {
      const config = getConfig();
      const db = getDatabase();

      const alienVaultClient = getAlienVaultClient();
      const virusTotalClient = getVirusTotalClient();

      const alienVaultApiValid = await alienVaultClient.validateApiKey().catch(() => false);

      return createToolResult(
        'Server Health Status',
        {
          server: {
            name: config.server.name,
            version: config.server.version,
            uptime: process.uptime(),
            nodeVersion: process.version,
          },
          database: {
            connected: db.isConnected(),
            path: config.database.path,
            encrypted: !!config.database.encryptionKey,
          },
          alienVault: {
            configured: !!config.alienVault.apiKey,
            apiValid: alienVaultApiValid,
            baseUrl: config.alienVault.baseUrl,
          },
          virusTotal: {
            configured: config.virusTotal.apiKeys.length > 0,
            apiKeyCount: config.virusTotal.apiKeys.length,
            baseUrl: config.virusTotal.baseUrl,
          },
        }
      );
    }
  );

  return server;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Creates a successful tool result.
 */
function createToolResult<T>(message: string, data?: T): ToolResult {
  const result: ToolResult = {
    content: [{ type: 'text', text: message }],
  };

  if (data) {
    result.content.push({
      type: 'text',
      text: JSON.stringify(data, null, 2),
    });
  }

  return result;
}

/**
 * Creates an error tool result.
 */
function createToolError<T>(message: string, data?: T): ToolResult {
  let errorString = '';
  try {
    errorString = JSON.stringify(data || {}, null, 2);
  } catch (e) {
    // Handle circular references
    errorString = String(data || {});
  }
  return {
    content: [{ type: 'text', text: message }],
    isError: true,
    error: errorString,
  };
}

// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * Main function to start the MCP server.
 */
async function main(): Promise<void> {
  const logger = createLogger();

  // Check required environment variables
  const missing = checkRequiredEnv();
  if (missing.length > 0) {
    console.error(getMissingEnvError(missing));
    logger.error('Missing required environment variables', { missing });
    process.exit(1);
  }

  // Validate configuration
  try {
    getConfig();
    logger.info('Configuration validated');
  } catch (error) {
    console.error('Configuration error:', error instanceof Error ? error.message : String(error));
    logger.error('Configuration validation failed', { error });
    process.exit(1);
  }

  // Start the MCP server
  logger.info('Starting AlienSec MCP Server...');
  
  serveStdio(createMcpServer);
  
  logger.info('AlienSec MCP Server running on stdio');
}

// ============================================================================
// Error Handling
// ============================================================================

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  const logger = createLogger();
  logger.error('Unhandled Promise Rejection', { reason, promise });
  console.error('Unhandled Promise Rejection:', reason);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  const logger = createLogger();
  logger.error('Uncaught Exception', { error });
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

// Handle SIGTERM for graceful shutdown
process.on('SIGTERM', () => {
  const logger = createLogger();
  logger.info('Received SIGTERM, shutting down gracefully...');
  
  try {
    const db = getDatabase();
    if (db.isConnected()) {
      db.disconnect();
      logger.info('Database connection closed');
    }
    
    resetAlienVaultClient();
    resetVirusTotalClient();
    resetDatabase();
    
    logger.info('Server shutdown complete');
  } catch (error) {
    logger.error('Error during shutdown', { error });
  } finally {
    process.exit(0);
  }
});

// Handle SIGINT for graceful shutdown
process.on('SIGINT', () => {
  const logger = createLogger();
  logger.info('Received SIGINT, shutting down gracefully...');
  process.emit('SIGTERM');
});

// ============================================================================
// Export for Testing
// ============================================================================

export {
  createMcpServer,
  createLogger,
  createToolResult,
  createToolError,
};

// ============================================================================
// Run the server
// ============================================================================

void main();
