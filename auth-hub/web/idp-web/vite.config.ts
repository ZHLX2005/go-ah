import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'

/**
 * 开发期把三类请求代理到本机 auth-hub（127.0.0.1:8080）：
 *   /api          页面配套 API（登录、授权确认、管理后台）
 *   /oauth2       OIDC 端点（授权 / 令牌 / 登出 / userinfo）
 *   /.well-known  发现文档与 JWKS
 *
 * 生产由 nginx 做同样的三件事，见同目录 nginx.conf。两处规则必须一致 ——
 * 尤其 /.well-known 容易被漏：漏了之后所有依赖方的 OIDC 初始化都会失败，
 * 而报错只出现在**调用方**的日志里，从认证中心这边看还以为一切正常。
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/oauth2': 'http://127.0.0.1:8080',
      '/.well-known': 'http://127.0.0.1:8080',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
})
