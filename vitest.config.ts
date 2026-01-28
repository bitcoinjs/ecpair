import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        globals: true,
        include: ['test/**/*.spec.ts'],
        exclude: ['test/integration/**/*.ts'],
        testTimeout: 10000,
        coverage: {
            provider: 'v8',
            reporter: ['text', 'lcov', 'html'],
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.d.ts'],
        },
    },
});
