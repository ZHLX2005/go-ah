import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

/**
 * 构建产物输出到 dist/，由 template-business-server(Go) 托管（部署方案A）
 *
 * 注意：openid-client 是面向 Node.js 设计的库，内部依赖 crypto / url / buffer /
 * process / util 等 Node 内置模块。在浏览器中直接打包会导致这些模块被替换为空对象，
 * 使 generators.codeVerifier() / codeChallenge() 在运行时抛错。
 * 因此这里显式注入 Node polyfill，保证 PKCE 参数生成在浏览器中可用。
 */
export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      include: ['crypto', 'buffer', 'process', 'util', 'stream', 'events', 'url', 'querystring', 'http', 'https', 'assert', 'zlib', 'path'],
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
    }),
  ],
  define: {
    // openid-client 内部会读取 process.env，浏览器下需提供空对象
    'process.env': '{}',
  },
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    port: 5174,
    // 开发阶段（部署方案B）代理业务 API 到 Go 后端
    proxy: {
      '/api': 'http://127.0.0.1:8081',
    },
  },
})
