import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    // Output to dist directory
    outDir: 'dist',
    // Generate source maps for debugging
    sourcemap: false,
    // Library mode for extracting CSS and JS
    lib: {
      entry: resolve(__dirname, 'main.ts'),
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
