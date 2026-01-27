import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 3004,
    host: true,
  },
  build: {
    target: 'esnext',
    outDir: 'dist',
  },
  esbuild: {
    jsxFactory: 'h',
    jsxFragment: 'Fragment',
    jsxInject: `import { h, Fragment } from 'preact'`,
  },
  optimizeDeps: {
    exclude: ['qcomm-wasm'],
  },
});
