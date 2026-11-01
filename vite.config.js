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
        this.emitFile({
          type: 'asset',
          fileName: 'kriptal.png',
          source: readFileSync(new URL('./kriptal.png', import.meta.url))
        });
        this.emitFile({
          type: 'asset',
          fileName: 'translations.js',
          source: readFileSync(new URL('./translations.js', import.meta.url))
        });
      }
    }
  ]
});
