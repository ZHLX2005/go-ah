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
#
# 刻意用 glibc 的 node:22-slim，而不是更小的 node:22-alpine。
#
# alpine 是 musl libc，vite/rollup/esbuild 的原生包在它上面叫
# @rollup/rollup-linux-x64-musl，而 glibc 上是 …-gnu。两套名字不通用，
# 一旦构建环境与 CI（ubuntu，glibc）不一致，就会出现「CI 过、镜像不过」
# 或者「装了包但找不到」这类只在某一侧复现的问题。
#
# 多阶段构建下构建镜像的体积不进最终产物（运行阶段只有 nginx + 静态文件），
# 所以这里没有理由为省体积去换 libc。
FROM node:22-slim AS build

WORKDIR /app

# 依赖清单先拷：源码变动时这一层仍命中缓存，省掉重复安装
#
# 只拷 package.json，不拷 package-lock.json —— 这是刻意为之：
# 仓库里的 lock 是在 Windows 上生成的，npm/cli#4828 导致它只收录了
# win32 平台的原生可选依赖，linux 的 rollup-gnu / esbuild-linux
# 条目整个缺失。npm ci 按锁文件装，装完 vite 直接找不到 rollup
# 原生模块。在容器内（Linux）用 npm install 现场解析依赖，平台一定正确。
COPY package.json ./

# 末尾断言原生包到位 —— 缺了就在这一层失败，而不是拖到 vite 阶段报一个
# 「Cannot find module @rollup/rollup-linux-x64-gnu」这种看不出所以然的错。
RUN npm install --no-audit --no-fund \
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
