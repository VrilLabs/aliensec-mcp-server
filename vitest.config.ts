import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    globals: true,
    environment: 'node',
    passWithNoTests: false,
    passWithNoMatchingTests: false,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*'],
      exclude: ['src/**/*.test.ts', 'src/**/*.spec.ts', 'node_modules/', 'dist/'],
    },
    include: ['src/**/*.test.ts', 'src/**/*.spec.ts'],
    exclude: ['node_modules/', 'dist/'],
    setupFiles: ['./src/test/setup.ts'],
    mockReset: false,
    clearMocks: true,
    restoreMocks: false,
    cache: {
      dir: './node_modules/.vitest',
    },
    threads: true,
    isolate: true,
    maxThreads: 4,
    minThreads: 1,
    silent: false,
    typecheck: {
      enabled: true,
      tsconfig: './tsconfig.json',
    },
  },
  resolve: {
    alias: {
      '@/*': '/src/*',
      '@config/*': '/src/config/*',
      '@core/*': '/src/core/*',
      '@database/*': '/src/database/*',
      '@tools/*': '/src/tools/*',
      '@types/*': '/src/types/*',
      '@utils/*': '/src/utils/*',
    },
  },
});
