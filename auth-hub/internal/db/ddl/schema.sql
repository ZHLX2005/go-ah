-- =============================================================================
-- auth-hub 表结构（幂等 DDL）
--
-- 这份 DDL 是 GORM AutoMigrate 的**等价替代**，字段名、类型、长度、索引名
-- 都与线上 auth_hub schema 里的现状逐一对应 —— 迁移到 GoFrame 后不再有
-- AutoMigrate（gdb 不提供该能力，也不该提供），建表改由本文件负责。
--
-- 为什么坚持幂等（IF NOT EXISTS）而不是"一次性手工执行"：
--   部署流水线是全自动的（push → 构建 → 滚动重启），没有人工介入的窗口。
--   启动时执行幂等 DDL 才能保持"部署完就能用"的原有体验；
--   同时它对已有库完全无害（表已存在则跳过，数据不受影响）。
--
-- 执行时机：internal/db 在建立连接、确保 schema 存在之后立即执行本文件
-- （通过 go:embed 内嵌，不依赖运行时文件路径）。
--
-- 表名说明：沿用 GORM 生成的复数/拆分命名（users、o_auth_clients…），
-- 因为线上已有数据；改名是一次无收益的数据迁移。
-- =============================================================================

CREATE TABLE IF NOT EXISTS "users" (
    "id"            BIGSERIAL PRIMARY KEY,
    "username"      VARCHAR(64)  NOT NULL,
    "password_hash" VARCHAR(255) NOT NULL,
    "email"         VARCHAR(128),
    "nickname"      VARCHAR(64),
    "is_admin"      BOOLEAN DEFAULT false,
    "created_at"    TIMESTAMPTZ,
    "updated_at"    TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS "idx_users_username" ON "users" ("username");

-- OIDC 客户端（业务方）。公共客户端使用 PKCE，不保存 client_secret。
-- 三个布尔开关都允许 NULL：历史行为是 nil 视为 true，
-- 与显式 false 区分开（见 entity.OAuthClient 的 IsXxx 方法）。
CREATE TABLE IF NOT EXISTS "o_auth_clients" (
    "id"               BIGSERIAL PRIMARY KEY,
    "client_id"        VARCHAR(64)  NOT NULL,
    "client_secret"    VARCHAR(255),
    "client_name"      VARCHAR(128),
    "redirect_uris"    TEXT,
    "scopes"           TEXT,
    "is_public"        BOOLEAN,
    "pkce_required"    BOOLEAN,
    "enabled"          BOOLEAN,
    "post_logout_uris" TEXT,
    "created_at"       TIMESTAMPTZ,
    "updated_at"       TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS "idx_o_auth_clients_client_id" ON "o_auth_clients" ("client_id");

-- 一次性授权码
CREATE TABLE IF NOT EXISTS "o_auth_authorization_codes" (
    "id"                    BIGSERIAL PRIMARY KEY,
    "code"                  VARCHAR(128) NOT NULL,
    "client_id"             VARCHAR(64)  NOT NULL,
    "user_id"               BIGINT       NOT NULL,
    "redirect_uri"          VARCHAR(255),
    "scope"                 VARCHAR(255),
    "nonce"                 VARCHAR(128),
    "code_challenge"        VARCHAR(128),
    "code_challenge_method" VARCHAR(16),
    "expires_at"            TIMESTAMPTZ,
    "used_at"               TIMESTAMPTZ,
    "created_at"            TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS "idx_o_auth_authorization_codes_code" ON "o_auth_authorization_codes" ("code");
CREATE INDEX IF NOT EXISTS "idx_o_auth_authorization_codes_client_id" ON "o_auth_authorization_codes" ("client_id");
CREATE INDEX IF NOT EXISTS "idx_o_auth_authorization_codes_user_id" ON "o_auth_authorization_codes" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_o_auth_authorization_codes_expires_at" ON "o_auth_authorization_codes" ("expires_at");

-- 刷新令牌（revoked_at 非空即已吊销）
CREATE TABLE IF NOT EXISTS "o_auth_refresh_tokens" (
    "id"         BIGSERIAL PRIMARY KEY,
    "token"      VARCHAR(128) NOT NULL,
    "client_id"  VARCHAR(64),
    "user_id"    BIGINT,
    "scope"      VARCHAR(255),
    "expires_at" TIMESTAMPTZ,
    "revoked_at" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS "idx_o_auth_refresh_tokens_token" ON "o_auth_refresh_tokens" ("token");
CREATE INDEX IF NOT EXISTS "idx_o_auth_refresh_tokens_client_id" ON "o_auth_refresh_tokens" ("client_id");
CREATE INDEX IF NOT EXISTS "idx_o_auth_refresh_tokens_user_id" ON "o_auth_refresh_tokens" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_o_auth_refresh_tokens_expires_at" ON "o_auth_refresh_tokens" ("expires_at");

-- 访问令牌（供 /oauth2/userinfo 做 Bearer 鉴权）
CREATE TABLE IF NOT EXISTS "o_auth_access_tokens" (
    "id"         BIGSERIAL PRIMARY KEY,
    "token"      VARCHAR(128) NOT NULL,
    "client_id"  VARCHAR(64),
    "user_id"    BIGINT,
    "scope"      VARCHAR(255),
    "expires_at" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS "idx_o_auth_access_tokens_token" ON "o_auth_access_tokens" ("token");
CREATE INDEX IF NOT EXISTS "idx_o_auth_access_tokens_client_id" ON "o_auth_access_tokens" ("client_id");
CREATE INDEX IF NOT EXISTS "idx_o_auth_access_tokens_user_id" ON "o_auth_access_tokens" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_o_auth_access_tokens_expires_at" ON "o_auth_access_tokens" ("expires_at");

-- 全局登录会话（IdP 侧 SSO 会话）
CREATE TABLE IF NOT EXISTS "user_sessions" (
    "id"         BIGSERIAL PRIMARY KEY,
    "session_id" VARCHAR(128) NOT NULL,
    "user_id"    BIGINT,
    "expires_at" TIMESTAMPTZ,
    "created_at" TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS "idx_user_sessions_session_id" ON "user_sessions" ("session_id");
CREATE INDEX IF NOT EXISTS "idx_user_sessions_user_id" ON "user_sessions" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_user_sessions_expires_at" ON "user_sessions" ("expires_at");

-- 持久化的 id_token 签名密钥（RSA 私钥，PKCS#8 PEM）。
-- 必须落库：密钥若只活在进程内存，每次重启都会换一把而 kid 不变，
-- 客户端缓存的 JWKS 立刻失配，表现为"重启后所有 id_token 验签失败"。
CREATE TABLE IF NOT EXISTS "signing_key_records" (
    "id"         BIGSERIAL PRIMARY KEY,
    "key_id"     VARCHAR(64) NOT NULL,
    "pem"        TEXT        NOT NULL,
    "created_at" TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS "idx_signing_key_records_key_id" ON "signing_key_records" ("key_id");
