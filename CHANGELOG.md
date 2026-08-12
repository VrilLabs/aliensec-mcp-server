# Changelog

All notable changes to AlienSec MCP Server are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-11

### Added

- Initial release of AlienSec MCP Server
- AlienVault OTX API integration with full functionality:
  - Search pulses
  - Get pulse details
  - Access indicators of compromise (IoCs)
  - Validate API keys
- VirusTotal API integration with:
  - File and URL scanning
  - Existing analysis retrieval
  - Multiple API key support with automatic rotation
  - Rate limiting (4 requests/minute per key)
  - Daily request limits (500/day per key)
  - Circuit breaker protection
- Endpoint scanning for multiple platforms:
  - macOS PKG installer
  - Windows PowerShell
  - Debian/APT
  - Redhat/RPM
- SQLite database with:
  - Scan result storage
  - API request logging
  - Circuit breaker event tracking
  - Optional encryption at rest
- MCP server implementation with:
  - Full tool registration
  - Error handling
  - Structured logging with Pino
  - Environment variable validation with Zod
  - Graceful shutdown

### Security

- API keys never logged or exposed in error messages
- Sensitive data hashed (SHA-256) before database storage
- All API communication uses HTTPS with TLS certificate validation
- Circuit breakers prevent cascading failures
- VirusTotal ToS compliance: multiple keys for redundancy only

### Testing

- Comprehensive test suite with Vitest (199 tests)
- Unit tests for all core modules
- Mock-based testing for API integrations
- Circuit breaker state testing

### Documentation

- Complete README with usage examples
- API documentation
- Configuration guide
- Troubleshooting section

## [Unreleased]

### Added

### Changed

### Fixed

### Security

### Deprecated

### Removed
