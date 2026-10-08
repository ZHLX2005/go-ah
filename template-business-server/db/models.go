package db

import "time"

// BusinessUser 业务侧用户（通过 IDP 的 sub 关联）
// 说明：业务平台不存储密码，身份完全来自 IDP 的 id_token
type BusinessUser struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Sub         string    `gorm:"uniqueIndex;size:64;not null" json:"sub"` // IDP 用户唯一标识
	Username    string    `gorm:"size:64" json:"username"`
	Nickname    string    `gorm:"size:64" json:"nickname"`
	Email       string    `gorm:"size:128" json:"email"`
	LastLoginAt time.Time `json:"last_login_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BusinessSession 业务侧会话
// 采用"方案1"：token 保存在后端，前端仅持有 session cookie
//
// Task4：AccessToken / RefreshToken / IDToken 落库前均经 AES-256-GCM 加密
// （见 package cryptox），数据库中不出现任何明文 JWT。
// 加密后的密文长度约为明文的 1.4 倍（base64 + salt + tag），
// 因此字段长度设为 text，同时保留 Encrypted 标记位用于存量明文迁移。
type BusinessSession struct {
	ID        uint   `gorm:"primaryKey"`
	SessionID string `gorm:"uniqueIndex;size:128;not null"`
	UserSub   string `gorm:"index;size:64"`

	// 以下三个字段存的是密文（base64(salt||nonce||ciphertext)）
	IDToken      string `gorm:"type:text"` // 由后端保管，不暴露给前端
	AccessToken  string `gorm:"type:text"`
	RefreshToken string `gorm:"type:text"`

	// Encrypted 标记本行 token 是否已加密存储
	// （迁移窗口期：历史明文行为 false，读取时不做解密）
	Encrypted bool `gorm:"not null;default:false"`

	// AccessTokenExpiresAt access_token 过期时间，后台续期协程据此判断
	AccessTokenExpiresAt time.Time `gorm:"index"`
	// RefreshTokenExpiresAt refresh_token 过期时间（默认 7 天）
	RefreshTokenExpiresAt time.Time

	// ExpiresAt 业务会话本身的有效期（8 小时，滑动续期）
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
	UpdatedAt time.Time
}
