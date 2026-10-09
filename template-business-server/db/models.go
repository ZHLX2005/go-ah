package db

import "time"

// BusinessUser 业务侧用户（通过 IDP 的 sub 关联）。
//
// 业务平台不存储密码：身份完全来自 IDP 的 id_token，本地这张表只是
// "谁是我们的用户"的索引加上一份资料缓存。
//
// 字段名与列的对应靠 json tag（gf 的 gconv 把 json tag 排在字段名前面），
// 因此不需要 orm tag；改 tag 等于改列名，别顺手改。
type BusinessUser struct {
	Id          uint      `json:"id"`
	Sub         string    `json:"sub"`
	Username    string    `json:"username"`
	Nickname    string    `json:"nickname"`
	Email       string    `json:"email"`
	LastLoginAt time.Time `json:"last_login_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BusinessSession 业务侧会话。
//
// 采用"方案1"：token 保存在后端，前端只持有 session cookie ——
// 浏览器里不放 JWT，一段 XSS 就偷不走登录态。
//
// IDToken / AccessToken / RefreshToken 三列落库前都经 AES-256-GCM 加密
// （见 cryptox），数据库里不出现明文 JWT。密文长度约为明文的 1.4 倍
// （base64 + salt + tag），所以列类型是 TEXT。
//
// Encrypted 是"存量明文"的迁移标记：历史行为 false，读取时不做解密
// （见 ReadTokens），避免把明文当密文解出乱码。
type BusinessSession struct {
	Id        uint   `json:"id"`
	SessionID string `json:"session_id"`
	UserSub   string `json:"user_sub"`

	// 以下三列存密文
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`

	Encrypted bool `json:"encrypted"`

	// AccessTokenExpiresAt 后台续期协程据此判断是否进入续期窗口
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at"`
	// RefreshTokenExpiresAt refresh_token 自身的过期时间（默认 7 天）
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`

	// ExpiresAt 业务会话本身的有效期（8 小时，滑动续期）
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
