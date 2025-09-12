import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./setupTests.ts'],
    exclude: [
      'node_modules/**',
      'dist/**',
      'build/**',
      'tests-e2e/**',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'clover'],
      exclude: [
        'node_modules/**',
        'dist/**',
        'build/**',
        'tests-e2e/**',
      ],
    },
  },
})


