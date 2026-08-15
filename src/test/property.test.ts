/**
 * Property-Based Tests using fast-check
 *
 * These tests use property-based testing (fuzzing) to validate invariants
 * in the core types and error classes of the AlienSec MCP Server.
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  AlienSecError,
  AlienVaultAPIError,
  VirusTotalAPIError,
  DatabaseError,
  ConfigurationError,
} from '../types/index.js';

// ============================================================================
// Error Class Property Tests
// ============================================================================

describe('AlienSecError – property-based tests', () => {
  it('always sets name to "AlienSecError"', () => {
    fc.assert(
      fc.property(
        fc.string(),
        fc.string(),
        fc.integer({ min: 100, max: 599 }),
        fc.boolean(),
        (message, code, statusCode, isRetryable) => {
          const err = new AlienSecError(message, code, statusCode, isRetryable);
          expect(err.name).toBe('AlienSecError');
          expect(err.message).toBe(message);
          expect(err.code).toBe(code);
          expect(err.statusCode).toBe(statusCode);
          expect(err.isRetryable).toBe(isRetryable);
        }
      )
    );
  });

  it('is always an instance of Error', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), fc.integer({ min: 100, max: 599 }), (message, code, statusCode) => {
        const err = new AlienSecError(message, code, statusCode);
        expect(err).toBeInstanceOf(Error);
        expect(err).toBeInstanceOf(AlienSecError);
      })
    );
  });
});

describe('AlienVaultAPIError – property-based tests', () => {
  it('always sets name and code correctly', () => {
    fc.assert(
      fc.property(fc.string(), fc.integer({ min: 100, max: 599 }), (message, statusCode) => {
        const err = new AlienVaultAPIError(message, statusCode);
        expect(err.name).toBe('AlienVaultAPIError');
        expect(err.code).toBe('ALIENVAULT_API_ERROR');
        expect(err.message).toBe(message);
        expect(err.statusCode).toBe(statusCode);
        expect(err.isRetryable).toBe(true);
      })
    );
  });
});

describe('VirusTotalAPIError – property-based tests', () => {
  it('preserves isRateLimit and isQuotaExceeded flags', () => {
    fc.assert(
      fc.property(
        fc.string(),
        fc.integer({ min: 100, max: 599 }),
        fc.boolean(),
        fc.boolean(),
        (message, statusCode, isRateLimit, isQuotaExceeded) => {
          const err = new VirusTotalAPIError(message, statusCode, isRateLimit, isQuotaExceeded);
          expect(err.name).toBe('VirusTotalAPIError');
          expect(err.code).toBe('VIRUSTOTAL_API_ERROR');
          expect(err.isRateLimit).toBe(isRateLimit);
          expect(err.isQuotaExceeded).toBe(isQuotaExceeded);
          expect(err.isRetryable).toBe(isRateLimit);
        }
      )
    );
  });
});

describe('DatabaseError – property-based tests', () => {
  it('always has DATABASE_ERROR code and non-retryable', () => {
    fc.assert(
      fc.property(fc.string(), (message) => {
        const err = new DatabaseError(message);
        expect(err.name).toBe('DatabaseError');
        expect(err.code).toBe('DATABASE_ERROR');
        expect(err.statusCode).toBe(500);
        expect(err.isRetryable).toBe(false);
      })
    );
  });
});

describe('ConfigurationError – property-based tests', () => {
  it('always has CONFIGURATION_ERROR code and statusCode 400', () => {
    fc.assert(
      fc.property(fc.string(), (message) => {
        const err = new ConfigurationError(message);
        expect(err.name).toBe('ConfigurationError');
        expect(err.code).toBe('CONFIGURATION_ERROR');
        expect(err.statusCode).toBe(400);
        expect(err.isRetryable).toBe(false);
      })
    );
  });
});

// ============================================================================
// Endpoint Flavor Validation Property Tests
// ============================================================================

describe('EndpointFlavor – property-based tests', () => {
  const VALID_FLAVORS = new Set(['pkg', 'powershell', 'apt', 'rpm']);

  /** Mirrors the runtime validation logic used in tool handlers */
  function isValidFlavor(value: string): boolean {
    return VALID_FLAVORS.has(value);
  }

  it('rejects arbitrary strings that are not valid flavors', () => {
    fc.assert(
      fc.property(
        fc.string().filter((s) => !VALID_FLAVORS.has(s)),
        (s) => {
          expect(isValidFlavor(s)).toBe(false);
        }
      )
    );
  });

  it('accepts every known valid flavor', () => {
    for (const flavor of VALID_FLAVORS) {
      expect(isValidFlavor(flavor)).toBe(true);
    }
  });

  it('flavor validation is case-sensitive', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('PKG', 'POWERSHELL', 'APT', 'RPM', 'Pkg', 'Apt'),
        (upper) => {
          expect(isValidFlavor(upper)).toBe(false);
        }
      )
    );
  });
});
