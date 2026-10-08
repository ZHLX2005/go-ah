import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// 构建产物输出到 dist/，由 auth-hub(Go) 直接托管（部署方案A）
export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    port: 5173,
    // 开发阶段（部署方案B）把 API / OIDC 请求代理到 Go 后端
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/oauth2': 'http://127.0.0.1:8080',
      '/.well-known': 'http://127.0.0.1:8080',
    },
  },
})
