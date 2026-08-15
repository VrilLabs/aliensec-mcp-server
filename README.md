<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/header.svg">
    <img alt="AlienSec MCP Server - Security Scanning Header" src="assets/header.svg" width="100%">
  </picture>
</div>

# AlienSec MCP Server
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/VrilLabs/aliensec-mcp-server/badge)](https://scorecard.dev/viewer/?uri=github.com/VrilLabs/aliensec-mcp-server)

**Production-Ready AlienVault OTX Endpoint Security Scanning MCP Server with VirusTotal Integration**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node-%3E%3D22.0.0-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6.3-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/Model_Context_Protocol-2.0.0-orange.svg)](https://modelcontextprotocol.io/)

---

## Overview

The **AlienSec MCP Server** is a production-grade Model Context Protocol (MCP) server that provides comprehensive endpoint security scanning capabilities using **AlienVault OTX** with optional **VirusTotal** integration.

This server enables AI agents and applications to perform security scans on various endpoint types (macOS PKG, Windows PowerShell, Debian APT, Redhat RPM) and retrieve threat intelligence from AlienVault OTX and VirusTotal APIs.

---

## Features

### Core Capabilities

- **Multi-Platform Endpoint Scanning**
  - Scan macOS systems using PKG installer flavor
  - Scan Windows endpoints via PowerShell
  - Scan Debian/Ubuntu systems using APT
  - Scan Redhat/CentOS systems using RPM

- **VirusTotal Integration**
  - Scan files and URLs using VirusTotal API
  - Retrieve existing analysis results
  - Automatic rate limiting and circuit breaker protection
  - Multiple API key support (respects VirusTotal ToS)

- **Threat Intelligence**
  - Search AlienVault OTX pulses
  - Retrieve pulse details and events
  - Access indicators of compromise (IoCs)

- **Data Persistence**
  - SQLite database with optional encryption
  - Scan result storage with timestamps
  - API request logging
  - Circuit breaker event tracking

- **Production-Ready Features**
  - Comprehensive error handling
  - Structured logging with Pino
  - Environment variable validation with Zod
  - Type-safe API schemas
  - Graceful shutdown handling

---

## Prerequisites

### System Requirements

- **Node.js**: >= 22.0.0
- **npm**: >= 8.0.0
- **Operating System**: macOS, Linux, or Windows
- **Disk Space**: Minimum 100MB for dependencies

### API Keys Required

1. **AlienVault OTX API Key** (Required)
   - Sign up at [https://otx.alienvault.com](https://otx.alienvault.com)
   - Navigate to **Settings** > **API Keys**
   - Generate a new API key

2. **VirusTotal API Key** (Optional, for enhanced functionality)
   - Sign up at [https://www.virustotal.com](https://www.virustotal.com)
   - Navigate to **API Console**
   - Generate API key(s)
   - Note: Free tier allows 500 requests/day, 4 requests/minute

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/VrilLabs/aliensec-mcp-server.git
cd aliensec-mcp-server
```

### 2. Install Dependencies

```bash
npm install
```

This will install all production and development dependencies.

### 3. Configure Environment Variables

Copy the example environment file and update with your API keys:

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

```env
# Server Configuration
NAME=aliensec-mcp-server
VERSION=1.0.0
DEBUG=false
LOG_LEVEL=info

# AlienVault OTX Configuration (Required)
ALIENVAULT_API_KEY=your_alienvault_api_key_here
ALIENVAULT_BASE_URL=https://api.agent.otxb.io
ALIENVAULT_DEFAULT_REGION=us-east-1

# VirusTotal Configuration (Optional)
VIRUSTOTAL_API_KEYS=key1,key2,key3
VIRUSTOTAL_BASE_URL=https://www.virustotal.com/api/v3
VIRUSTOTAL_RATE_LIMIT_PER_MINUTE=4
VIRUSTOTAL_DAILY_LIMIT=500
VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT=300

# Database Configuration
DATABASE_PATH=./data/aliensec.db
DATABASE_ENCRYPTION_KEY=your_encryption_key_here
DATABASE_TIMEOUT=5000
```

> **Note**: VirusTotal ToS prohibits using multiple API keys to bypass rate limits. This implementation respects those limits and uses multiple keys for redundancy only.

### 4. (Optional) Install SQLite Encryption Dependencies

For encrypted database support on Linux/macOS:

```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# macOS
xcode-select --install
```

---

## Usage

### Development Mode

Run the server in development mode with automatic reloading:

```bash
npm run dev
```

### Production Mode

Build and run the server:

```bash
npm run build
npm start
```

### Using with MCP Clients

The server communicates via **stdio** (standard input/output). To use it with an MCP client:

```bash
# Direct execution
node dist/index.js

# Or using the npm script
npm start
```

### Example MCP Client Integration

```typescript
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const client = new Client({ name: 'my-client', version: '1.0.0' });
const transport = new StdioClientTransport({
  command: 'node',
  args: ['dist/index.js'],
});

await client.connect(transport);

// Call a scan tool
const result = await client.callTool({
  name: 'scan_macos_pkg',
  arguments: {
    target: '192.168.1.100',
    useVirusTotal: true,
  },
});

console.log(result.content);
```

---

## Available Tools

### Scan Tools (5)

| Tool | Description | Parameters |
|------|-------------|------------|
| `scan_endpoint` | Generic endpoint scanner | `flavor`, `target`, `useVirusTotal`, `apiKeyIndex` |
| `scan_macos_pkg` | Scan macOS PKG installer | `target`, `useVirusTotal` |
| `scan_windows` | Scan Windows endpoint | `target`, `useVirusTotal` |
| `scan_debian_apt` | Scan Debian/APT endpoint | `target`, `useVirusTotal` |
| `scan_redhat_rpm` | Scan Redhat/RPM endpoint | `target`, `useVirusTotal` |

### VirusTotal Tools (2)

| Tool | Description | Parameters |
|------|-------------|------------|
| `use_virustotal` | Scan resource with VirusTotal | `resource`, `apiKeyIndex`, `wait` |
| `get_virustotal_analysis` | Get existing VirusTotal analysis | `hash`, `apiKeyIndex` |

### AlienVault OTX Tools (3)

| Tool | Description | Parameters |
|------|-------------|------------|
| `get_bootstrap_command` | Get bootstrap command for flavor | `flavor`, `target` |
| `get_bootstrap_urls` | Get all bootstrap URLs | - |
| `search_pulses` | Search AlienVault OTX pulses | `query`, `limit`, `offset` |

### Database Tools (4)

| Tool | Description | Parameters |
|------|-------------|------------|
| `get_scan_stats` | Get scan statistics | - |
| `get_recent_scans` | Get recent scans | `limit` |
| `get_circuit_breaker_stats` | Get circuit breaker stats | - |
| `get_api_stats` | Get API statistics | - |

### System Tools (1)

| Tool | Description | Parameters |
|------|-------------|------------|
| `get_health` | Get server health status | - |

---

## Bootstrap Commands

The server provides pre-configured bootstrap commands for each endpoint flavor. `<api-key>` below is your resolved `ALIENVAULT_API_KEY` value, and `TARGET=<target>` is only included when a `target` is provided.

### macOS PKG Installer
```bash
API_KEY=<api-key> [TARGET=<target>] bash -c "$(curl -s https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=pkg)"
```

### Windows PowerShell
```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; API_KEY=<api-key> (new-object Net.WebClient).DownloadString("https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=powershell") | iex; install_agent -apikey <api-key> [-target <target>]
```

### Debian APT
```bash
API_KEY=<api-key> [TARGET=<target>] bash -c "$(curl -s https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=apt)"
```

### Redhat RPM
```bash
API_KEY=<api-key> [TARGET=<target>] bash -c "$(curl -s https://api.agent.otxb.io/osquery-api-otx/bootstrap?flavor=rpm)"
```

---

## Project Structure

```
aliensec-mcp-server/
├── src/
│   ├── config/
│   │   └── index.ts           # Environment configuration & validation
│   ├── core/
│   │   ├── alienVault.ts      # AlienVault OTX API client
│   │   └── virusTotal.ts      # VirusTotal API client
│   ├── database/
│   │   └── index.ts           # SQLite database with repositories
│   ├── types/
│   │   └── index.ts           # TypeScript type definitions
│   └── index.ts               # Main MCP server entry point
├── package.json
├── tsconfig.json
├── .env.example
├── .gitignore
├── eslint.config.js
├── .prettierrc
└── README.md
```

---

## Architecture

### Layered Design

```
┌─────────────────────────────────────┐
│           MCP Server Layer           │  ← src/index.ts
├─────────────────────────────────────┤
│         Core Service Layer           │  ← src/core/
├─────────────────────────────────────┤
│         Data Access Layer            │  ← src/database/
├─────────────────────────────────────┤
│        Configuration Layer           │  ← src/config/
├─────────────────────────────────────┤
│           Type Definitions           │  ← src/types/
└─────────────────────────────────────┘
```

### Key Design Patterns

1. **Singleton Pattern**: Database, AlienVault client, VirusTotal client
2. **Repository Pattern**: ScanRepository, CircuitBreakerRepository, APILogRepository
3. **Circuit Breaker Pattern**: Automatic API key rotation on failures
4. **Token Bucket Rate Limiter**: Rate limiting for VirusTotal API
5. **Factory Pattern**: MCP server creation with dependency injection
6. **Strategy Pattern**: Different scan flavors with common interface

---

## Database Schema

The server uses SQLite with the following tables:

### scan_records
Stores all scan results with findings, VirusTotal data, and timestamps.

### circuit_breaker_events
Tracks circuit breaker state changes for API keys.

### api_logs
Logs all API requests with response times, status codes, and errors.

### schema_version
Tracks database schema version for migrations.

---

## Error Handling

### Custom Error Classes

- **AlienSecError**: Base error class with code and statusCode
- **AlienVaultAPIError**: AlienVault-specific errors
- **VirusTotalAPIError**: VirusTotal-specific errors with rate limit detection
- **DatabaseError**: Database-related errors
- **ConfigurationError**: Configuration validation errors

### Error Response Format

Tool errors return the standard MCP result shape with `isError: true`. The human-readable message is the first content block; `error` carries the JSON-stringified context data (scan ID, flavor, target, etc.) that triggered the failure:

```json
{
  "content": [
    { "type": "text", "text": "Scan failed: <error message>" }
  ],
  "isError": true,
  "error": "{\n  \"scanId\": \"...\",\n  \"flavor\": \"pkg\",\n  \"target\": \"...\",\n  \"error\": \"<error message>\"\n}"
}
```

---

## Logging

The server uses **Pino** for structured logging with the following levels:

- **error**: Critical failures
- **warn**: Warnings and potential issues
- **info**: Normal operations and status updates
- **debug**: Detailed debugging information
- **trace**: Very verbose logging for development

Logs are automatically redacted to prevent sensitive data (API keys) from being logged.

---

## Rate Limiting & Circuit Breaker

### VirusTotal Rate Limiting

- **Token Bucket Algorithm**: Smooth rate limiting
- **Configurable Limits**: Set via environment variables
- **Automatic Wait**: Option to wait when rate limited
- **Circuit Breaker**: Automatically blocks API keys that fail repeatedly

### Circuit Breaker Configuration

- **Failure Threshold**: 5 consecutive failures
- **Reset Timeout**: 300 seconds (5 minutes)
- **Half-Open State**: Test with 1 request before fully reopening

### ToS Compliance

The implementation **respects VirusTotal's Terms of Service**:

- Multiple API keys are for **redundancy**, not for bypassing limits
- Each API key respects individual rate limits
- Circuit breaker prevents rapid retries on failures
- Daily request counting prevents quota exhaustion

---

## Development

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run with coverage
npx vitest run --coverage
```

### Linting & Formatting

```bash
# Run linting
npm run lint

# Auto-fix linting issues
npm run lint:fix

# Format code
npm run format
```

### Type Checking

```bash
npm run typecheck
```

### Build Verification

```bash
# Clean build
npm run clean
npm run build

# Check build output
ls -la dist/
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ALIENVAULT_API_KEY` | Yes | - | AlienVault OTX API key |
| `ALIENVAULT_BASE_URL` | No | `https://api.agent.otxb.io` | AlienVault API base URL |
| `ALIENVAULT_DEFAULT_REGION` | No | `us-east-1` | Default region for agents |
| `VIRUSTOTAL_API_KEYS` | No | `` | Comma-separated VirusTotal API keys |
| `VIRUSTOTAL_BASE_URL` | No | `https://www.virustotal.com/api/v3` | VirusTotal API base URL |
| `VIRUSTOTAL_RATE_LIMIT_PER_MINUTE` | No | `4` | Rate limit per minute |
| `VIRUSTOTAL_DAILY_LIMIT` | No | `500` | Daily request limit |
| `VIRUSTOTAL_CIRCUIT_BREAKER_TIMEOUT` | No | `300` | Circuit breaker timeout (seconds) |
| `DATABASE_PATH` | No | `./data/aliensec.db` | SQLite database path |
| `DATABASE_ENCRYPTION_KEY` | No | - | Database encryption key |
| `DATABASE_TIMEOUT` | No | `5000` | Database connection timeout |
| `NAME` | No | `aliensec-mcp-server` | Server name |
| `VERSION` | No | `1.0.0` | Server version |
| `DEBUG` | No | `false` | Enable debug mode |
| `LOG_LEVEL` | No | `info` | Log level (error, warn, info, debug, trace) |

---

## Security Considerations

### Data Protection

1. **Database Encryption**: Use `DATABASE_ENCRYPTION_KEY` for encrypting sensitive data at rest
2. **API Key Security**: API keys are never logged; use environment variables or secure vaults
3. **Memory Safety**: Sensitive strings are hashed with PBKDF2 (120,000 iterations) before storage in circuit breaker and API log tables

### Network Security

1. **HTTPS Only**: All API communication uses HTTPS
2. **Certificate Validation**: TLS certificate validation is enabled by default
3. **User-Agent**: Custom user agent identifies the server version

### Rate Limiting

1. **Client-Side Rate Limiting**: Prevents overwhelming external APIs
2. **Circuit Breaker**: Prevents cascading failures
3. **Backpressure**: Automatic waiting when rate limited

---

## Performance

### Optimizations

- **Connection Pooling**: Database connections are reused
- **Lazy Loading**: Repositories are created on-demand
- **Indexed Queries**: Database tables have appropriate indexes
- **Caching**: API key hashes are cached for circuit breaker checks
- **Async/Await**: Non-blocking I/O operations

### Benchmarks

- **Scan Request**: ~100-500ms (simulated)
- **VirusTotal Request**: ~200-1000ms (network dependent)
- **Database Operations**: <10ms (local SQLite)

---

## Troubleshooting

### Common Issues

#### Database Connection Failed

```
Error: Failed to connect to database
```

**Solution**: Ensure the data directory exists and has write permissions:

```bash
mkdir -p data
chmod 755 data
```

#### Missing ALIENVAULT_API_KEY

```
Missing required environment variables:
  - ALIENVAULT_API_KEY
```

**Solution**: Set the environment variable:

```bash
export ALIENVAULT_API_KEY=your_api_key_here
# or add to .env file
```

#### VirusTotal Rate Limit Exceeded

```
Error: Rate limit exceeded for API key 0
```

**Solution**: 
- Wait for the rate limit to reset (default: 4 requests/minute)
- Add more API keys (comma-separated in VIRUSTOTAL_API_KEYS)
- Use `wait: true` parameter to automatically wait

#### Circuit Breaker Open

```
Error: API key 0 is blocked by circuit breaker
```

**Solution**: Wait for the circuit breaker timeout to expire (default: 5 minutes). The circuit will automatically reopen after the timeout.

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
DEBUG=true LOG_LEVEL=debug npm run dev
```

---

## Contributing

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Commit Message Guidelines

- Use **Conventional Commits** format
- Prefix with type: `feat:`, `fix:`, `docs:`, `style:`, `refactor:`, `test:`, `chore:`
- Keep subject line under 72 characters
- Provide detailed description in body if needed

### Code Review

- All PRs require approval from at least one maintainer
- CI/CD pipeline must pass (lint, typecheck, tests)
- Code must follow existing patterns and style

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **Model Context Protocol**: [https://modelcontextprotocol.io](https://modelcontextprotocol.io)
- **AlienVault OTX**: [https://otx.alienvault.com](https://otx.alienvault.com)
- **VirusTotal**: [https://www.virustotal.com](https://www.virustotal.com)
- **TypeScript**: [https://www.typescriptlang.org](https://www.typescriptlang.org)
- **Zod**: [https://github.com/colinhacks/zod](https://github.com/colinhacks/zod)
- **Pino**: [https://github.com/pinojs/pino](https://github.com/pinojs/pino)
- **better-sqlite3-multiple-ciphers**: [https://github.com/m4heshd/better-sqlite3-multiple-ciphers](https://github.com/m4heshd/better-sqlite3-multiple-ciphers)

---

## References

- [AlienVault OTX Documentation](https://otx.alienvault.com/documentation)
- [VirusTotal API Documentation](https://docs.virustotal.com/docs/api-overview)
- [Model Context Protocol Specification](https://github.com/modelcontextprotocol/specification)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)

---

**Built with ❤️ for the security community**
