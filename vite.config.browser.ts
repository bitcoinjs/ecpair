import { resolve } from 'path';
import { defineConfig } from 'vite';
import dts from 'vite-plugin-dts';

export default defineConfig({
    build: {
        outDir: 'browser',
        emptyOutDir: true,
        target: 'esnext',
        minify: 'esbuild',
        lib: {
            entry: resolve(__dirname, 'src/index.ts'),
            formats: ['es'],
            fileName: () => 'index.js',
        },
        rollupOptions: {
            external: ['wif', '@noble/curves/secp256k1', '@noble/curves/abstract/modular'],
            output: {
                chunkFileNames: 'chunks/[name]-[hash].js',
            },
        },
    },
    plugins: [
        dts({
            outDir: 'browser',
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.test.ts', 'src/**/*.spec.ts', 'test/**/*'],
            insertTypesEntry: true,
            copyDtsFiles: true,
        }),
    ],
});
