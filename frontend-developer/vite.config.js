import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Hostnames Vite will answer to. Vite blocks unknown Host headers by default, which would stop the
// site from opening through VS Code port forwarding (Dev Tunnels) or GitHub Codespaces.
const allowedHosts = ['localhost', '127.0.0.1', '.devtunnels.ms', '.app.github.dev']

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: { allowedHosts },
  preview: { allowedHosts },
})
