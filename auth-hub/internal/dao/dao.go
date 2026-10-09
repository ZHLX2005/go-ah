// Package dao 是**访问数据表的唯一出口**。
//
// 业务代码只写 dao.User.Ctx(ctx).Where(...)，不出现表名字符串、不出现
// g.DB()、不自己拼 SQL。好处有三：
//   - 表名/列名集中在 consts 与 dao/internal，改结构时只需改一处；
//   - Safe() 让没有 Where 的 Update/Delete 直接报错，堵掉"全表误更新"；
//   - 测试可以把整棵树指向一次性 schema（见 db.SetInstance）。
package dao

import (
	"context"

	"github.com/gogf/gf/v2/database/gdb"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao/internal"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
)

// ── users ───────────────────────────────────────────────────────────────────

type userDao struct{}

// User 用户表
var User = userDao{}

// Ctx 返回带上下文的查询模型
func (userDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableUser).Safe().Ctx(ctx)
}

// Table 表名
func (userDao) Table() string { return consts.TableUser }

// Columns 列名集合
func (userDao) Columns() internal.UserColumns { return internal.UserColumnsOf() }

// Tx 返回**绑定在事务上**的模型（跨表原子写入用，见 invitationCodeDao.Tx 的说明）
func (userDao) Tx(tx gdb.TX) *gdb.Model {
	return tx.Model(consts.TableUser).Safe()
}

// ── o_auth_clients ──────────────────────────────────────────────────────────

type oauthClientDao struct{}

// OAuthClient OIDC 客户端表
var OAuthClient = oauthClientDao{}

// Ctx 返回带上下文的查询模型
func (oauthClientDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableOAuthClient).Safe().Ctx(ctx)
}

// Table 表名
func (oauthClientDao) Table() string { return consts.TableOAuthClient }

// Columns 列名集合
func (oauthClientDao) Columns() internal.OAuthClientColumns { return internal.OAuthClientColumnsOf() }

// ── o_auth_authorization_codes ──────────────────────────────────────────────

type oauthAuthorizationCodeDao struct{}

// OAuthAuthorizationCode 授权码表
var OAuthAuthorizationCode = oauthAuthorizationCodeDao{}

// Ctx 返回带上下文的查询模型
func (oauthAuthorizationCodeDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableOAuthAuthorizationCode).Safe().Ctx(ctx)
}

// Table 表名
func (oauthAuthorizationCodeDao) Table() string { return consts.TableOAuthAuthorizationCode }

// Columns 列名集合
func (oauthAuthorizationCodeDao) Columns() internal.OAuthAuthorizationCodeColumns {
	return internal.OAuthAuthorizationCodeColumnsOf()
}

// ── o_auth_refresh_tokens ───────────────────────────────────────────────────

type oauthRefreshTokenDao struct{}

// OAuthRefreshToken 刷新令牌表
var OAuthRefreshToken = oauthRefreshTokenDao{}

// Ctx 返回带上下文的查询模型
func (oauthRefreshTokenDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableOAuthRefreshToken).Safe().Ctx(ctx)
}

// Table 表名
func (oauthRefreshTokenDao) Table() string { return consts.TableOAuthRefreshToken }

// Columns 列名集合
func (oauthRefreshTokenDao) Columns() internal.OAuthRefreshTokenColumns {
	return internal.OAuthRefreshTokenColumnsOf()
}

// ── o_auth_access_tokens ────────────────────────────────────────────────────

type oauthAccessTokenDao struct{}

// OAuthAccessToken 访问令牌表
var OAuthAccessToken = oauthAccessTokenDao{}

// Ctx 返回带上下文的查询模型
func (oauthAccessTokenDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableOAuthAccessToken).Safe().Ctx(ctx)
}

// Table 表名
func (oauthAccessTokenDao) Table() string { return consts.TableOAuthAccessToken }

// Columns 列名集合
func (oauthAccessTokenDao) Columns() internal.OAuthAccessTokenColumns {
	return internal.OAuthAccessTokenColumnsOf()
}

// ── user_sessions ───────────────────────────────────────────────────────────

type userSessionDao struct{}

// UserSession 全局会话表
var UserSession = userSessionDao{}

// Ctx 返回带上下文的查询模型
func (userSessionDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableUserSession).Safe().Ctx(ctx)
}

// Table 表名
func (userSessionDao) Table() string { return consts.TableUserSession }

// Columns 列名集合
func (userSessionDao) Columns() internal.UserSessionColumns { return internal.UserSessionColumnsOf() }

// ── signing_key_records ─────────────────────────────────────────────────────

type signingKeyDao struct{}

// SigningKey 签名密钥表
var SigningKey = signingKeyDao{}

// Ctx 返回带上下文的查询模型
func (signingKeyDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableSigningKey).Safe().Ctx(ctx)
}

// Table 表名
func (signingKeyDao) Table() string { return consts.TableSigningKey }

// Columns 列名集合
func (signingKeyDao) Columns() internal.SigningKeyColumns { return internal.SigningKeyColumnsOf() }

// ── invitation_codes ────────────────────────────────────────────────────────

type invitationCodeDao struct{}

// InvitationCode 注册邀请码表
var InvitationCode = invitationCodeDao{}

// Ctx 返回带上下文的查询模型
func (invitationCodeDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableInvitationCode).Safe().Ctx(ctx)
}

// Tx 返回**绑定在事务上**的模型。
//
// 为什么必须另开一个入口：Ctx 拿到的模型挂在连接池上，**不在任何事务里** ——
// 用它执行的语句会自己独立提交。核销邀请码这种"扣次数 + 建账号 + 写明细"
// 要么全成要么全不成，只要有一句走的是 Ctx，回滚就漏掉了它，
// 而漏掉的那句永远是"看起来成功、事后才发现"的一类。
//
// 表名依然只出现在 dao 内部：调用方拿到的是模型，不是 SQL。
func (invitationCodeDao) Tx(tx gdb.TX) *gdb.Model {
	return tx.Model(consts.TableInvitationCode).Safe()
}

// Table 表名
func (invitationCodeDao) Table() string { return consts.TableInvitationCode }

// Columns 列名集合
func (invitationCodeDao) Columns() internal.InvitationCodeColumns {
	return internal.InvitationCodeColumnsOf()
}

// ── invitation_code_usages ──────────────────────────────────────────────────

type invitationCodeUsageDao struct{}

// InvitationCodeUsage 邀请码使用明细表
var InvitationCodeUsage = invitationCodeUsageDao{}

// Ctx 返回带上下文的查询模型
func (invitationCodeUsageDao) Ctx(ctx context.Context) *gdb.Model {
	return db.Instance().Model(consts.TableInvitationCodeUsage).Safe().Ctx(ctx)
}

// Tx 返回绑定在事务上的模型（见 invitationCodeDao.Tx 的说明）
func (invitationCodeUsageDao) Tx(tx gdb.TX) *gdb.Model {
	return tx.Model(consts.TableInvitationCodeUsage).Safe()
}

// Table 表名
func (invitationCodeUsageDao) Table() string { return consts.TableInvitationCodeUsage }

// Columns 列名集合
func (invitationCodeUsageDao) Columns() internal.InvitationCodeUsageColumns {
	return internal.InvitationCodeUsageColumnsOf()
}
