/**
 * Property-Based Tests using fast-check
 *
 * These tests use property-based testing (fuzzing) to validate invariants
 * in the core types and error classes of the AlienSec MCP Server.
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  ENDPOINT_FLAVORS,
  ENDPOINT_FLAVOR_SCHEMA,
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
      fc.property(fc.string(), message => {
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
      fc.property(fc.string(), message => {
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
  const VALID_FLAVORS = new Set(ENDPOINT_FLAVORS);
  const INVALID_CASE_VARIANTS = Array.from(
    new Set(ENDPOINT_FLAVORS.flatMap(flavor => [flavor.toUpperCase(), `${flavor[0].toUpperCase()}${flavor.slice(1)}`]))
  ).filter(variant => !VALID_FLAVORS.has(variant));
  const [FIRST_INVALID_CASE_VARIANT, ...OTHER_INVALID_CASE_VARIANTS] = INVALID_CASE_VARIANTS;

  it('rejects arbitrary strings that are not valid flavors', () => {
    fc.assert(
      fc.property(
        fc.string().filter(s => !VALID_FLAVORS.has(s)),
        s => {
          expect(ENDPOINT_FLAVOR_SCHEMA.safeParse(s).success).toBe(false);
        }
      )
    );
  });

  it('accepts every known valid flavor', () => {
    for (const flavor of VALID_FLAVORS) {
      expect(ENDPOINT_FLAVOR_SCHEMA.safeParse(flavor).success).toBe(true);
    }
  });

  it('flavor validation is case-sensitive', () => {
    expect(FIRST_INVALID_CASE_VARIANT).toBeDefined();

    fc.assert(
      fc.property(fc.constantFrom(FIRST_INVALID_CASE_VARIANT!, ...OTHER_INVALID_CASE_VARIANTS), upper => {
        expect(ENDPOINT_FLAVOR_SCHEMA.safeParse(upper).success).toBe(false);
      })
    );
  });
});
