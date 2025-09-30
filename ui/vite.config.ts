import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist'
  },
  server: {
    host: '0.0.0.0',
    port: 5174,
    strictPort: true,
    watch: {
      usePolling: true, // Required for Docker volume mounts
      interval: 1000,
    },
    hmr: {
      // Enable HMR for Docker environment
      clientPort: 5174,
    },
  },
})
