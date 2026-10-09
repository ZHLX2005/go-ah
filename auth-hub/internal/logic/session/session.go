// Package session 管理 IdP 侧的全局登录会话（SSO 会话）。
//
// 会话是整个单点登录的根：业务方（gs-ac）只持有自己的 JWT，
// 而"是否需要重新输密码"由这里的会话决定。销毁会话必须连带吊销
// 该用户已签发的令牌，否则会出现"登出后旧 access_token 还能用"。
package session

import (
	"context"
	"time"

	"github.com/gogf/gf/v2/frame/g"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// Issue 创建全局会话，返回会话 ID 与 Cookie 有效期。
func Issue(ctx context.Context, userID int64) (sid string, ttl time.Duration, err error) {
	sid = utility.RandomToken(32)
	now := time.Now()
	_, err = dao.UserSession.Ctx(ctx).Data(g.Map{
		"session_id": sid,
		"user_id":    userID,
		"expires_at": now.Add(consts.SessionTTL),
		"created_at": now,
	}).Insert()
	if err != nil {
		return "", 0, err
	}
	return sid, consts.SessionTTL, nil
}

// CurrentUser 按会话 ID 取当前登录用户。
//
// 返回 (nil, nil) 表示"没有有效会话"——这是正常的未登录状态，
// 不是错误；调用方据此走跳转登录页的分支，不要去区分错误类型。
// 会话过期与用户被删一律按未登录处理。
func CurrentUser(ctx context.Context, sid string) (*entity.User, error) {
	if sid == "" {
		return nil, nil
	}
	var s entity.UserSession
	found, err := db.ScanOne(ctx, dao.UserSession.Ctx(ctx).
		Where("session_id", sid).
		Where("expires_at >", time.Now()), &s)
	if err != nil {
		return nil, err
	}
	if !found {
		// 会话不存在与已过期都按"未登录"处理，不区分
		return nil, nil
	}
	var u entity.User
	found, err = db.ScanOne(ctx, dao.User.Ctx(ctx).Where("id", s.UserID), &u)
	if err != nil {
		return nil, err
	}
	if !found {
		// 会话还在但用户已不存在（被删）：同样按未登录处理
		return nil, nil
	}
	return &u, nil
}

// Destroy 销毁指定会话，并吊销该用户全部 refresh_token、清空其 access_token。
//
// 三件事必须一起做：只删会话的话，业务方手里的 refresh_token 仍能换新
// id_token，用户会看到"登出后又被静默登录回来"。
func Destroy(ctx context.Context, sid string) error {
	if sid == "" {
		return nil
	}
	var s entity.UserSession
	found, err := db.ScanOne(ctx, dao.UserSession.Ctx(ctx).Where("session_id", sid), &s)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}

	now := time.Now()
	if _, err := dao.OAuthRefreshToken.Ctx(ctx).
		Where("user_id", s.UserID).
		Where("revoked_at IS NULL").
		Data(g.Map{"revoked_at": now}).
		Update(); err != nil {
		return err
	}
	if _, err := dao.OAuthAccessToken.Ctx(ctx).
		Where("user_id", s.UserID).
		Delete(); err != nil {
		return err
	}
	if _, err := dao.UserSession.Ctx(ctx).
		Where("session_id", sid).
		Delete(); err != nil {
		return err
	}
	g.Log().Infof(ctx, "[auth-hub] 已销毁全局会话 user=%d，并吊销其全部令牌", s.UserID)
	return nil
}

// DestroyAllForUser 销毁某用户的全部会话与令牌（管理操作/安全事件用）
func DestroyAllForUser(ctx context.Context, userID int64) error {
	now := time.Now()
	if _, err := dao.OAuthRefreshToken.Ctx(ctx).
		Where("user_id", userID).
		Where("revoked_at IS NULL").
		Data(g.Map{"revoked_at": now}).
		Update(); err != nil {
		return err
	}
	if _, err := dao.OAuthAccessToken.Ctx(ctx).Where("user_id", userID).Delete(); err != nil {
		return err
	}
	_, err := dao.UserSession.Ctx(ctx).Where("user_id", userID).Delete()
	return err
}
