import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/xensql': {
        target: 'http://localhost:8900',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/xensql/, ''),
      },
      '/queryvault': {
        target: 'http://localhost:8950',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/queryvault/, ''),
      },
    },
  },
})
