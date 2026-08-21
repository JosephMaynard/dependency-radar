import { defineConfig } from 'vite';
import { resolve } from 'path';
import { fileURLToPath } from 'url';

// This config is ESM (.mts), so __dirname does not exist. Derived here rather
// than using import.meta.dirname so the file does not carry a Node 20.11 floor.
const configDir = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
  build: {
    // Output to dist directory
    outDir: 'dist',
    // Generate source maps for debugging
    sourcemap: false,
    // Library mode for extracting CSS and JS
    lib: {
      entry: resolve(configDir, 'main.ts'),
      name: 'DependencyRadarReport',
      fileName: 'report',
      formats: ['iife'],
    },
    rollupOptions: {
      output: {
        // Ensure CSS is extracted to a separate file
        assetFileNames: 'report.[ext]',
      },
    },
    // Minify for production
    minify: 'terser',
    terserOptions: {
      format: {
        comments: false,
      },
    },
  },
  // Development server config
  server: {
    port: 5173,
    open: true,
  },
});
