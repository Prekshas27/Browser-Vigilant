import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { resolve } from 'path'

export default defineConfig({
  plugins: [svelte()],
  base: "./",   // REQUIRED for Chrome/Edge extensions — generates relative asset paths
  build: {
    outDir: '../dist-popup',
    emptyOutDir: true,
    rollupOptions: {
      input: resolve(__dirname, 'index.html'),
    }
  }
})
