import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';

export default defineConfig({
  base: process.env.BASE_PATH || '/',
  plugins: [
    {
      name: 'copy-root-stylesheet',
      generateBundle() {
        this.emitFile({
          type: 'asset',
          fileName: 'styles.css',
          source: readFileSync(new URL('./styles.css', import.meta.url), 'utf8')
        });
      }
    }
  ]
});
