# =============================================================================
# 统一登录平台前端镜像：node 构建 → nginx 托管 + 反向代理
#
# 与 auth-hub 的 Go 镜像组成两个容器：
#   Auth-hub-web (本镜像)  ← 公网入口，托管 SPA 并反代 /api、/oauth2、/.well-known
#   auth-hub     (Go)      ← 只提供 API 与 OIDC 端点
#
# 这样拆之后，auth-hub 的 Go 镜像**不再需要构建与内嵌前端**（见根目录 Dockerfile），
# 构建更快、镜像更小，职责也更单一。
# =============================================================================

# ── 阶段 1：构建 SPA ──────────────────────────────────────────────────────
FROM node:22-alpine AS build

WORKDIR /app

# 依赖清单先拷：源码变动时这一层仍命中缓存，省掉重复安装
COPY package.json package-lock.json ./

# 依赖安装。
#
# 优先 npm ci（严格按 lock 装，可复现），但 npm 有个跨平台的已知缺陷
# (npm/cli#4828)：lock 里只解析了「生成 lock 的那个平台」的原生 optional 包。
# 换到 Linux 后 npm ci 可能装不出 @rollup/rollup-linux-x64-gnu 与
# @esbuild/linux-x64，构建会在 vite 阶段抛「Cannot find module ...」——
# 这个报错看起来像代码问题，其实与代码无关，很容易查偏。
#
# 所以这里 ci 之后**直接验产物**：缺了就回退 npm install 重新解析依赖树。
RUN npm ci --no-audit --no-fund \
 && if [ ! -d node_modules/@rollup/rollup-linux-x64-gnu ] || [ ! -d node_modules/@esbuild/linux-x64 ]; then \
      echo "[deps] npm ci 未装齐 Linux 原生包，回退到 npm install 重新解析依赖树"; \
      rm -rf node_modules; \
      npm install --no-audit --no-fund; \
    fi \
 && test -d node_modules/@rollup/rollup-linux-x64-gnu \
 && test -d node_modules/@esbuild/linux-x64

COPY . .
# 构建带 tsc -b 类型检查：类型错误在这里就失败，而不是等运行期才发现
RUN npm run build


# ── 阶段 2：nginx 托管 ────────────────────────────────────────────────────
FROM nginx:1.27-alpine

# 覆盖默认站点配置（SPA fallback + 三类后端路径反代）
COPY nginx.conf /etc/nginx/conf.d/default.conf

COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

# 前置检查：配置语法错就起不来，比容器起来后 404 好查
RUN nginx -t

CMD ["nginx", "-g", "daemon off;"]
