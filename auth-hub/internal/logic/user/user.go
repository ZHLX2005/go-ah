// Package user 处理本地账号的查询与口令校验。
//
// 平台引入统一登录后，本地口令登录只保留给 IdP 自身的管理后台使用，
// 但校验逻辑仍必须严谨：口令错误与账号不存在返回**不同**的原因码，
// 是为了让管理后台能给出可操作的提示；面向公网时若要防账号枚举，
// 应在上层把两者合并成同一提示，而不是在这里糊掉信息。
package user

import (
	"context"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// AuthError 口令登录失败的原因（ErrorCode 直接对应接口响应里的 error 字段）
type AuthError struct {
	ErrorCode string
	Message   string
}

// Error 实现 error 接口
func (e *AuthError) Error() string { return e.Message }

// FindByUsername 按账号查用户；不存在返回 (nil, nil)
func FindByUsername(ctx context.Context, username string) (*entity.User, error) {
	var u entity.User
	found, err := db.ScanOne(ctx, dao.User.Ctx(ctx).Where("username", username), &u)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &u, nil
}

// FindByID 按主键查用户；不存在返回 (nil, nil)
func FindByID(ctx context.Context, id int64) (*entity.User, error) {
	var u entity.User
	found, err := db.ScanOne(ctx, dao.User.Ctx(ctx).Where("id", id), &u)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &u, nil
}

// Authenticate 校验账号口令，成功返回用户
func Authenticate(ctx context.Context, username, password string) (*entity.User, error) {
	u, err := FindByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, &AuthError{ErrorCode: "user_not_found", Message: "账号不存在"}
	}
	if !utility.VerifyPassword(password, u.PasswordHash) {
		return nil, &AuthError{ErrorCode: "wrong_password", Message: "密码错误"}
	}
	return u, nil
}
