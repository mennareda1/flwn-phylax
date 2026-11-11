import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';
import { defineConfig } from 'vitest/config';

// The build is ONE html file (scripts, styles and fonts inside), so the demo opens with a double click, offline, from any folder.
export default defineConfig({
  base: './',
  plugins: [react(), viteSingleFile()],
  server: { host: '127.0.0.1' },
  build: { target: 'es2022' },
  test: { environment: 'jsdom', globals: true, setupFiles: ['./test/setup.js'], css: false, include: ['test/**/*.test.{js,jsx}'] },
});
