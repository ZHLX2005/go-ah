package api

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gogf/gf/v2/frame/g"

	v1 "github.com/ZHLX2005/go-ah/template-business-server/api/v1"
	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// currentSession 读取业务 session cookie 并校验有效期。
//
// 返回 (nil, nil) 表示"未登录或已过期"——这是**正常的业务结果**，不是错误；
// 与 (nil, err) 的区别很重要：前者对应"请重新登录"，后者是数据库故障。
// 迁移前的实现把两者都折成 nil，于是数据库连不上时前端会看到"未登录"，
// 排查方向完全被带偏。这里把它们分开。
func currentSession(ctx context.Context) (*db.BusinessSession, error) {
	r := g.RequestFromCtx(ctx)

	sid := r.Cookie.Get(SessionCookie).String()
	if sid == "" {
		return nil, nil
	}
	return db.SessionByID(ctx, sid)
}

// ============================================================
// 接口 3：GET /api/session —— 轻量登录态（供前端首页判断）
//
// 未登录也返回 200 + {code:0, data:null}：首页要用它决定显示"登录"入口
// 还是用户名，401 会让前端把它当成请求失败而不是"没登录"。
// ============================================================

// SessionInfo 返回当前业务会话的轻量信息
func (c *Controller) SessionInfo(ctx context.Context) error {
	r := g.RequestFromCtx(ctx)

	sess, err := currentSession(ctx)
	if err != nil {
		writeError(r, http.StatusInternalServerError, "db_error", err.Error())
		return nil
	}
	if sess == nil {
		writeJSON(r, http.StatusOK, &v1.SessionRes{Code: 0, Data: nil})
		return nil
	}
	writeJSON(r, http.StatusOK, &v1.SessionRes{
		Code: 0,
		Data: &v1.SessionData{Sub: sess.UserSub, ExpiresAt: sess.ExpiresAt},
	})
	return nil
}

// ============================================================
// 接口 4：GET /api/profile —— 受保护接口
//
// 通过业务 session cookie 鉴权，返回用户资料。
// token 内容绝不下发，只给 has_* 布尔标记。
// ============================================================

// Profile 返回当前用户资料与会话状态
func (c *Controller) Profile(ctx context.Context) error {
	r := g.RequestFromCtx(ctx)

	sess, err := currentSession(ctx)
	if err != nil {
		writeError(r, http.StatusInternalServerError, "db_error", err.Error())
		return nil
	}
	if sess == nil {
		writeError(r, http.StatusUnauthorized, "unauthorized", "未登录或会话已过期")
		return nil
	}

	bu, err := db.UserBySub(ctx, sess.UserSub)
	if err != nil {
		writeError(r, http.StatusInternalServerError, "db_error", err.Error())
		return nil
	}
	if bu == nil {
		writeError(r, http.StatusUnauthorized, "user_not_found", "")
		return nil
	}

	// 读取解密后的 token 元信息，仅返回布尔标记，绝不把 token 内容下发给前端
	tokens, err := ReadTokens(sess)
	if err != nil {
		log.Printf("[BIZ] 会话 %s token 解密失败: %v", sess.SessionID, err)
		writeError(r, http.StatusInternalServerError, "token_decrypt_failed", "会话 token 解密失败，可能需要重新登录")
		return nil
	}

	writeJSON(r, http.StatusOK, &v1.ProfileRes{
		Code: 0,
		Data: v1.ProfileData{
			Sub:                   bu.Sub,
			Username:              bu.Username,
			Nickname:              bu.Nickname,
			Email:                 bu.Email,
			LastLoginAt:           bu.LastLoginAt,
			SessionExpiresAt:      sess.ExpiresAt,
			HasIDToken:            tokens.IDToken != "",
			HasRefreshToken:       tokens.RefreshToken != "",
			TokenEncrypted:        sess.Encrypted,
			AccessTokenExpiresAt:  sess.AccessTokenExpiresAt,
			RefreshTokenExpiresAt: sess.RefreshTokenExpiresAt,
		},
	})
	return nil
}

// ============================================================
// 接口 5：POST /api/logout —— 统一登出
//
// 1) 清空业务会话
// 2) 返回 IDP 登出地址（携带 id_token_hint），由前端跳转完成单点登出
//
// 只做第一步是不够的：业务会话没了，但 IDP 的登录态还在，用户再点登录
// 会"静默"回到已登录状态 —— 看起来像登出失败。
// ============================================================

// Logout 销毁业务会话并给出 IDP 登出地址
func (c *Controller) Logout(ctx context.Context) error {
	r := g.RequestFromCtx(ctx)

	sess, err := currentSession(ctx)
	if err != nil {
		writeError(r, http.StatusInternalServerError, "db_error", err.Error())
		return nil
	}

	idTokenHint := ""
	if sess != nil {
		// id_token 为密文存储，登出回调需要明文，因此先解密
		if tokens, derr := ReadTokens(sess); derr == nil {
			idTokenHint = tokens.IDToken
		} else {
			log.Printf("[BIZ] 登出时解密 id_token 失败: %v", derr)
		}
		// 删不掉也要继续往下走：让浏览器先清 cookie 并跳去 IDP 登出，
		// 比在这里回 500 把用户卡在"已登录"状态要好
		if derr := db.DeleteSession(ctx, sess.SessionID); derr != nil {
			log.Printf("[BIZ] 删除业务会话失败 session=%s: %v", sess.SessionID, derr)
		}
	}
	setSessionCookie(r, "", -1)

	params := url.Values{}
	if idTokenHint != "" {
		params.Set("id_token_hint", idTokenHint)
	}
	params.Set("post_logout_redirect_uri", PostLogoutURI)
	params.Set("client_id", ClientID)

	writeJSON(r, http.StatusOK, &v1.LogoutRes{
		Code:      0,
		Message:   "业务会话已销毁",
		LogoutURL: strings.TrimSuffix(IDPIssuer, "/") + "/oauth2/logout?" + params.Encode(),
		IDPLogout: true,
	})
	return nil
}
