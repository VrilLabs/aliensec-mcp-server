/**
 * AlienSec MCP Server - AlienVault OTX Integration Module
 * 
 * Provides AlienVault OTX endpoint scanning capabilities.
 * Uses osquery-based agents to scan different endpoint types.
 */

import fetch from 'node-fetch';
import { z } from 'zod';
import * as crypto from 'crypto';
import {
  AlienVaultConfig,
  ScanRequest,
  ScanResult,
  ScanFinding,
  EndpointFlavor,
  AlienVaultAPIError,
  ConfigurationError,
} from '../types';
import { getConfig } from '../config';
import { getDatabase } from '../database';

// ============================================================================
// Bootstrap Script URLs
// ============================================================================

const BOOTSTRAP_URLS: Record<EndpointFlavor, string> = {
  pkg: 'https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=pkg',
  powershell: 'https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=powershell',
  apt: 'https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=apt',
  rpm: 'https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=rpm',
};

// ============================================================================
// AlienVault API Response Schemas
// ============================================================================

const alienVaultPulseSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  reference: z.string().url().optional(),
  tags: z.array(z.string()).optional(),
  indicators: z.array(
    z.object({
      type: z.string(),
      value: z.string(),
      description: z.string().optional(),
    })
  ).optional(),
  malware_families: z.array(z.string()).optional(),
  adversaries: z.array(z.string()).optional(),
  target_countries: z.array(z.string()).optional(),
  created: z.string(),
  modified: z.string(),
  author: z.string().optional(),
  severity: z.number().min(1).max(100).optional(),
  confidence: z.number().min(0).max(100).optional(),
});

const alienVaultEventSchema = z.object({
  id: z.string(),
  pulse_id: z.string(),
  title: z.string(),
  description: z.string().optional(),
  timestamp: z.string(),
  ioc: z.string(),
  ioc_type: z.string(),
  severity: z.number().optional(),
  confidence: z.number().optional(),
  tags: z.array(z.string()).optional(),
  destination_ip: z.string().optional(),
  destination_port: z.number().optional(),
  destination_url: z.string().url().optional(),
  source_ip: z.string().ip().optional(),
  source_country: z.string().optional(),
});

const alienVaultScanResultSchema = z.object({
  query_name: z.string(),
  query: z.string(),
  results: z.array(
    z.object({
      host: z.string(),
      path: z.string(),
      value: z.string(),
      time: z.number(),
    })
  ),
  matches: z.array(
    z.object({
      pulse: alienVaultPulseSchema,
      event: alienVaultEventSchema,
      match_type: z.string(),
      match_value: z.string(),
    })
  ),
});

// ============================================================================
// AlienVault OTX Client
// ============================================================================

/**
 * AlienVault OTX API client for endpoint scanning.
 */
export class AlienVaultClient {
  private readonly config: AlienVaultConfig;
  private readonly database;

  constructor(config: AlienVaultConfig = getConfig().alienVault) {
    this.config = config;
    this.database = getDatabase();
  }

  /**
   * Generates the bootstrap command for a specific endpoint flavor.
   */
  getBootstrapCommand(flavor: EndpointFlavor, target?: string): string {
    const url = BOOTSTRAP_URLS[flavor];
    if (!url) {
      throw new ConfigurationError(`Unknown endpoint flavor: ${flavor}`);
    }

    const apiKeyParam = `API_KEY=${this.config.apiKey}`;
    const targetParam = target ? `TARGET=${target}` : '';
    
    // Generate the appropriate command based on the flavor
    switch (flavor) {
      case 'pkg':
        return `${apiKeyParam} ${targetParam} bash -c "$(curl -s ${url})"`;
      
      case 'powershell':
        return `[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; ${apiKeyParam} (new-object Net.WebClient).DownloadString("${url}") | iex; install_agent -apikey ${this.config.apiKey}${target ? ` -target ${target}` : ''}`;
      
      case 'apt':
        return `${apiKeyParam} ${targetParam} bash -c "$(curl -s ${url})"`;
      
      case 'rpm':
        return `${apiKeyParam} ${targetParam} bash -c "$(curl -s ${url})"`;
      
      default:
        throw new ConfigurationError(`Unsupported endpoint flavor: ${flavor}`);
    }
  }

  /**
   * Executes a scan for a specific endpoint flavor.
   * In a real implementation, this would execute the bootstrap script
   * on the target endpoint and collect results.
   */
  async scan(request: ScanRequest): Promise<ScanResult> {
    const scanId = crypto.randomBytes(16).toString('hex');
    const timestamp = new Date();
    const target = request.target || 'localhost';

    try {
      // Generate the bootstrap command
      const command = this.getBootstrapCommand(request.flavor, request.target);

      // In a real implementation, this would execute the command on the target
      // For now, we'll simulate a scan with some sample findings
      const scanResult = await this.simulateScan(
        scanId,
        request.flavor,
        target,
        request.options
      );

      // Save to database
      const db = getDatabase();
      const repo = db.getScanRepository();
      repo.saveScanResult(scanResult);

      return scanResult;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);

      const failedResult: ScanResult = {
        scanId,
        timestamp,
        flavor: request.flavor,
        target,
        status: 'failed',
        threatsDetected: 0,
        warnings: 0,
        findings: [],
        error: errorMessage,
      };

      // Save to database
      const db = getDatabase();
      const repo = db.getScanRepository();
      repo.saveScanResult(failedResult);

      throw new AlienVaultAPIError(errorMessage, 500, {
        scanId,
        flavor: request.flavor,
        target,
      });
    }
  }

  /**
   * Simulates a scan execution (placeholder for actual implementation).
   * In production, this would execute the osquery agent on the target endpoint.
   */
  private async simulateScan(
    scanId: string,
    flavor: EndpointFlavor,
    target: string,
    options?: { customQuery?: string; useVirusTotal?: boolean }
  ): Promise<ScanResult> {
    // Simulate scan execution delay
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Generate sample findings based on the target
    const findings = this.generateSampleFindings(flavor, target);

    // Count threats and warnings
    const threatsDetected = findings.filter(
      (f) => f.severity === 'critical' || f.severity === 'high'
    ).length;
    const warnings = findings.filter(
      (f) => f.severity === 'medium' || f.severity === 'low'
    ).length;

    // Add VirusTotal results if requested
    let virusTotal: any = undefined;
    if (options?.useVirusTotal) {
      virusTotal = await this.simulateVirusTotalScan(target);
    }

    return {
      scanId,
      timestamp: new Date(),
      flavor,
      target,
      status: 'success',
      threatsDetected,
      warnings,
      findings,
      virusTotal,
      rawOutput: JSON.stringify({
        scanId,
        flavor,
        target,
        timestamp: new Date().toISOString(),
        findings: findings.map((f) => ({
          id: f.id,
          severity: f.severity,
          type: f.type,
          description: f.description,
        })),
      }, null, 2),
    };
  }

  /**
   * Generates sample findings for demonstration purposes.
   */
  private generateSampleFindings(flavor: EndpointFlavor, target: string): ScanFinding[] {
    const findings: ScanFinding[] = [];

    // Simulate some findings based on the target
    if (target.toLowerCase().includes('test') || target.toLowerCase().includes('demo')) {
      findings.push({
        id: crypto.randomBytes(8).toString('hex'),
        severity: 'high',
        type: 'suspicious',
        description: 'Suspicious process detected on the endpoint',
        affected: `/usr/bin/${flavor}_process`,
        iocs: ['malicious_hash_123', 'suspicious_ip_456'],
        confidence: 85,
        source: 'alienvault',
        remediation: 'Investigate the suspicious process and check for indicators of compromise',
      });

      findings.push({
        id: crypto.randomBytes(8).toString('hex'),
        severity: 'medium',
        type: 'vulnerability',
        description: 'Outdated package version detected',
        affected: 'openssl-1.0.2',
        iocs: ['CVE-2021-12345', 'openssl-1.0.2'],
        confidence: 90,
        source: 'alienvault',
        remediation: 'Update openssl to the latest version',
      });
    }

    // Add informational finding
    findings.push({
      id: crypto.randomBytes(8).toString('hex'),
      severity: 'info',
      type: 'policy_violation',
      description: 'Endpoint scanned successfully',
      affected: target,
      iocs: [],
      confidence: 100,
      source: 'alienvault',
    });

    return findings;
  }

  /**
   * Simulates a VirusTotal scan for demonstration purposes.
   */
  private async simulateVirusTotalScan(resource: string): Promise<any> {
    // Simulate VirusTotal API call
    await new Promise((resolve) => setTimeout(resolve, 200));

    // Generate sample VirusTotal result
    return {
      scanId: crypto.randomBytes(16).toString('hex'),
      apiKeyIndex: 0,
      timestamp: new Date(),
      positives: 2,
      total: 70,
      results: {
        'Kaspersky': {
          engine: 'Kaspersky',
          name: 'Trojan.Generic',
          category: 'malicious',
          confidence: 95,
          raw: { result: 'Trojan.Generic' },
        },
        'Bitdefender': {
          engine: 'Bitdefender',
          name: 'Suspicious.Generic',
          category: 'suspicious',
          confidence: 80,
          raw: { result: 'Suspicious.Generic' },
        },
      },
      permalink: `https://www.virustotal.com/gui/file/${crypto.randomBytes(16).toString('hex')}`,
    };
  }

  /**
   * Gets information about a specific pulse (threat intelligence feed).
   */
  async getPulse(pulseId: string): Promise<z.infer<typeof alienVaultPulseSchema>> {
    const url = `${this.config.baseUrl}/pulses/${pulseId}`;

    try {
      const response = await this.makeRequest(url, {
        headers: {
          'X-OTX-API-KEY': this.config.apiKey,
          'Accept': 'application/json',
        },
      });

      const data = await response.json();
      return alienVaultPulseSchema.parse(data);
    } catch (error) {
      throw new AlienVaultAPIError(
        `Failed to fetch pulse ${pulseId}: ${error instanceof Error ? error.message : String(error)}`,
        500,
        { pulseId }
      );
    }
  }

  /**
   * Searches for pulses matching specific criteria.
   */
  async searchPulses(
    query: string,
    limit: number = 20,
    offset: number = 0
  ): Promise<{
    count: number;
    pulses: z.infer<typeof alienVaultPulseSchema>[];
  }> {
    const url = `${this.config.baseUrl}/pulses/search?query=${encodeURIComponent(query)}&limit=${limit}&offset=${offset}`;

    try {
      const response = await this.makeRequest(url, {
        headers: {
          'X-OTX-API-KEY': this.config.apiKey,
          'Accept': 'application/json',
        },
      });

      const data = await response.json();
      
      return {
        count: data.count || 0,
        pulses: (data.pulses || []).map((pulse: unknown) => alienVaultPulseSchema.parse(pulse)),
      };
    } catch (error) {
      throw new AlienVaultAPIError(
        `Failed to search pulses: ${error instanceof Error ? error.message : String(error)}`,
        500,
        { query, limit, offset }
      );
    }
  }

  /**
   * Gets recent events for a specific pulse.
   */
  async getPulseEvents(
    pulseId: string,
    limit: number = 20,
    offset: number = 0
  ): Promise<z.infer<typeof alienVaultEventSchema>[]> {
    const url = `${this.config.baseUrl}/pulses/${pulseId}/events?limit=${limit}&offset=${offset}`;

    try {
      const response = await this.makeRequest(url, {
        headers: {
          'X-OTX-API-KEY': this.config.apiKey,
          'Accept': 'application/json',
        },
      });

      const data = await response.json();
      return (data.events || []).map((event: unknown) => alienVaultEventSchema.parse(event));
    } catch (error) {
      throw new AlienVaultAPIError(
        `Failed to fetch pulse events: ${error instanceof Error ? error.message : String(error)}`,
        500,
        { pulseId, limit, offset }
      );
    }
  }

  /**
   * Gets Indicators of Compromise (IoCs) from a specific pulse.
   */
  async getPulseIndicators(pulseId: string): Promise<Array<{
    type: string;
    value: string;
    description?: string;
  }>> {
    const url = `${this.config.baseUrl}/pulses/${pulseId}/indicators`;

    try {
      const response = await this.makeRequest(url, {
        headers: {
          'X-OTX-API-KEY': this.config.apiKey,
          'Accept': 'application/json',
        },
      });

      const data = await response.json();
      return data.indicators || [];
    } catch (error) {
      throw new AlienVaultAPIError(
        `Failed to fetch pulse indicators: ${error instanceof Error ? error.message : String(error)}`,
        500,
        { pulseId }
      );
    }
  }

  /**
   * Makes an HTTP request to the AlienVault OTX API.
   */
  private async makeRequest(url: string, options: RequestInit = {}): Promise<Response> {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'User-Agent': 'aliensec-mcp-server/1.0.0',
      },
    });

    if (!response.ok) {
      const errorData = await this.tryParseError(response);
      throw new Error(
        errorData?.error?.message || 
        `AlienVault OTX API request failed with status ${response.status}`
      );
    }

    return response;
  }

  /**
   * Tries to parse the error response from AlienVault OTX API.
   */
  private async tryParseError(response: Response): Promise<unknown> {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  /**
   * Validates that the AlienVault API key is valid and has access to the API.
   */
  async validateApiKey(): Promise<boolean> {
    const url = `${this.config.baseUrl}/pulses/subscriptions`;

    try {
      const response = await this.makeRequest(url, {
        headers: {
          'X-OTX-API-KEY': this.config.apiKey,
          'Accept': 'application/json',
        },
      });

      return response.ok;
    } catch {
      return false;
    }
  }
}

// ============================================================================
// Singleton Client Instance
// ============================================================================

let alienVaultClientInstance: AlienVaultClient | null = null;

/**
 * Gets the singleton AlienVault client instance.
 */
export function getAlienVaultClient(): AlienVaultClient {
  if (!alienVaultClientInstance) {
    alienVaultClientInstance = new AlienVaultClient();
  }
  return alienVaultClientInstance;
}

/**
 * Resets the singleton AlienVault client instance. Useful for testing.
 */
export function resetAlienVaultClient(): void {
  alienVaultClientInstance = null;
}

/**
 * Creates a new AlienVault client with custom configuration.
 * Useful for testing or multi-tenant scenarios.
 */
export function createAlienVaultClient(config: AlienVaultConfig): AlienVaultClient {
  return new AlienVaultClient(config);
}

// ============================================================================
// Export Bootstrap URLs
// ============================================================================

export { BOOTSTRAP_URLS };
