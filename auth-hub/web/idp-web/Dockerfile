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
COPY package.json package-lock.json ./

# 依赖安装：npm ci 严格按 lock 装，可复现。
# 末尾断言原生包到位 —— 缺了就在这一层失败，而不是拖到 vite 阶段报一个
# 「Cannot find module @rollup/rollup-linux-x64-gnu」这种看不出所以然的错。
#
# 注意：lock 文件必须与 package.json 同步。两者不同步时 npm ci 会直接
# EUSAGE 退出（这是好事，比静默装错版本强），用
#   npm install --package-lock-only
# 重新生成即可 —— 本仓库此前就因此挂过一次。
RUN npm ci --no-audit --no-fund \
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
