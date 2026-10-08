# =============================================================================
# auth-hub 认证中心镜像（纯后端）
#
# 三个模块里只打包 auth-hub：它是统一登录平台本体（IdP）。
# template-business-server 是接入示例、oidc-cli 是命令行客户端，
# 都不是服务端部署物，各自按 release.yml 的二进制分发即可。
#
# **本镜像不含前端**：idp-web 已改由 nginx 容器托管（见
# auth-hub/web/idp-web/Dockerfile），两个容器共享 docker 网络：
#     auth-hub-web (nginx)  ← 公网入口，托管 SPA 并反代 /api、/oauth2、/.well-known
#     auth-hub     (本镜像) ← 只提供 API 与 OIDC 端点
# 这样拆的好处：Go 镜像不再需要 node 构建阶段，构建快、体积小、职责单一。
# main.go 里若找不到 web/idp-web/dist 会打印一行提示，仅提供 API，属预期行为。
#
# 构建上下文 = 仓库根目录（go-ah/），因此 COPY 路径都带 auth-hub/ 前缀。
#
# 存储：PostgreSQL（与 gs-ac 共享同一实例，auth-hub 落在独立 schema，
# 由 IDP_DSN 的 search_path 决定，默认 auth_hub）。
# 换成 PG 后 gorm 驱动是纯 Go（pgx），不再需要 cgo —— 因此
# CGO_ENABLED=0 静态编译，builder 阶段也不必装 build-base。
# =============================================================================

# ── 阶段 1：编译 auth-hub ─────────────────────────────────────────────────
# Go 1.25：gorm.io/driver/postgres 与 jackc/pgx v5 都要求 go >= 1.25.0，
# go.mod 的 go 指令因此被抬到 1.25.0，基础镜像必须跟上。
FROM golang:1.25-alpine AS builder

WORKDIR /src
ENV GOPROXY=https://goproxy.cn,direct

# 先只拷 go.mod/go.sum：依赖未变时 go mod download 这一层直接命中缓存
COPY auth-hub/go.mod auth-hub/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY auth-hub/ ./

ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/auth-hub .


# ── 阶段 2：运行 ──────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /out/auth-hub ./auth-hub

EXPOSE 8080

ENV TZ=Asia/Shanghai \
    IDP_ADDR=0.0.0.0:8080

# 启动前必须由部署方注入的变量（刻意不给默认值）：
#   IDP_DSN              PostgreSQL 连接串，search_path 决定落哪个 schema，
#                        例如 postgres://user:pw@host:5432/postgres?sslmode=disable&search_path=auth_hub
#   IDP_ISSUER           **对外可达地址 = nginx 前端的地址**，例如 http://<server>:8082
#                        （前端改由 nginx 托管后，issuer 必须指向 nginx，
#                          因为 authorization/end_session 端点由浏览器访问）
#   GSAC_REDIRECT_URI    gs-ac 前端回调白名单（空格分隔多个）
#   GSAC_POST_LOGOUT_URI gs-ac 统一登出回跳白名单
#
# 可选：
#   IDP_SIGNING_KEY_PEM  固定 RSA 私钥（PKCS#8 PEM）。多副本部署时各实例
#                        必须共用同一把，否则各自生成会导致验签互相失败。
#                        单实例不配也可，密钥会持久化在库里、跨重启稳定。
CMD ["./auth-hub"]
