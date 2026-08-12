/**
 * Test Setup File
 * This file is automatically loaded before all tests by Vitest
 */

import { beforeAll, afterAll, afterEach, vi } from 'vitest';

// Note: better-sqlite3-multiple-ciphers is NOT mocked here globally.
// Each test file that needs to mock this module should set up its own mock.
// This avoids conflicts with database.test.ts which has its own MockDatabase definition.
//
// The database.test.ts, alienVault.test.ts, and virusTotal.test.ts files each define
// their own MockDatabase class and mock the better-sqlite3-multiple-ciphers module.

// Mock node-fetch globally
const mockFetch = vi.fn();
vi.mock('node-fetch', () => ({
  default: mockFetch,
}));

// Mock pino logger globally
const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  child: vi.fn(() => mockLogger),
};
vi.mock('pino', () => ({
  default: vi.fn(() => mockLogger),
}));

// Note: config and database modules are NOT mocked here globally.
// Individual test files that need these modules mocked should set up
// their own mocks to avoid affecting config.test.ts and database.test.ts
// which test the actual implementations.

// Mock environment variables for testing
process.env.ALIENVAULT_API_KEY = 'test-alienvault-api-key';
process.env.VIRUSTOTAL_API_KEYS = 'test-vt-key-1,test-vt-key-2';
process.env.DATABASE_PATH = ':memory:';

// Global test setup
beforeAll(() => {
  // Setup code that runs once before all tests
});

afterAll(() => {
  // Cleanup code that runs once after all tests
});

afterEach(() => {
  // Cleanup after each test
  vi.clearAllMocks();
  // vi.resetAllMocks();
  // vi.restoreAllMocks();
});

// Export test utilities
export const TEST_ALIENVAULT_API_KEY = 'test-alienvault-api-key';
export const TEST_VIRUSTOTAL_API_KEYS = ['test-vt-key-1', 'test-vt-key-2'];
export { mockFetch, mockLogger };
