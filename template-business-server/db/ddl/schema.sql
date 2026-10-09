-- template-business-server 的业务表结构（SQLite）
--
-- 随二进制内嵌分发（go:embed），不依赖运行时文件路径：部署只需要
-- 一个可执行文件加一个空的 .db 文件，不额外分发 .sql。
--
-- 语句全部 IF NOT EXISTS，每次启动重复执行是幂等的。这也是"不引入迁移框架"
-- 的代价：改表结构时只能**追加**语句，不能在原语句上修改 —— 老库里的表已经
-- 建好了，改原语句对它不起作用。

CREATE TABLE IF NOT EXISTS business_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sub           TEXT NOT NULL,
    username      TEXT,
    nickname      TEXT,
    email         TEXT,
    last_login_at DATETIME,
    created_at    DATETIME,
    updated_at    DATETIME
);

-- sub 是 IDP 的稳定用户标识，一个 sub 只能有一行
CREATE UNIQUE INDEX IF NOT EXISTS idx_business_users_sub ON business_users (sub);

CREATE TABLE IF NOT EXISTS business_sessions (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id               TEXT NOT NULL,
    user_sub                 TEXT,

    -- 以下三列存的是密文：base64( salt(16) || nonce(12) || ciphertext+tag )
    -- 数据库中不出现任何明文 JWT（见 cryptox 包）
    id_token                 TEXT,
    access_token             TEXT,
    refresh_token            TEXT,

    -- encrypted 标记本行 token 是否已加密。
    -- 迁移窗口期：历史明文行为 0，读取时不做解密（见 ReadTokens）。
    encrypted                INTEGER NOT NULL DEFAULT 0,

    access_token_expires_at  DATETIME,
    refresh_token_expires_at DATETIME,

    -- 业务会话本身的有效期（默认 8 小时，滑动续期）
    expires_at               DATETIME,
    created_at               DATETIME,
    updated_at               DATETIME
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_business_sessions_session_id ON business_sessions (session_id);
CREATE INDEX IF NOT EXISTS idx_business_sessions_user_sub ON business_sessions (user_sub);
-- 后台续期协程按 access_token 到期时间挑会话，会话清理按 expires_at 挑
CREATE INDEX IF NOT EXISTS idx_business_sessions_access_token_expires_at ON business_sessions (access_token_expires_at);
CREATE INDEX IF NOT EXISTS idx_business_sessions_expires_at ON business_sessions (expires_at);
