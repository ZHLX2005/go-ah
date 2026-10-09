package admin

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/ZHLX2005/go-ah/auth-hub/api/admin/v1"
	// 与控制器同名的逻辑层包：本包（controller/admin）也叫 admin，
	// 用别名区分，避免读代码时误以为是本包类型。
	logicadmin "github.com/ZHLX2005/go-ah/auth-hub/internal/logic/admin"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
)

// TestClientView_NeverLeaksSecret 管理端视图不得泄露 client_secret。
//
// 这是靠类型而不是靠"记得别赋值"保证的：v1.AdminClientView 里根本没有
// secret 字段，所以序列化结果里不可能出现它。
func TestClientView_NeverLeaksSecret(t *testing.T) {
	const secret = "cs_0123456789abcdef0123456789abcdef"
	cl := entity.OAuthClient{
		Id:           1,
		ClientID:     "some-client",
		ClientSecret: secret,
		ClientName:   "某客户端",
		RedirectURIs: "http://127.0.0.1:8081/oauth/callback",
		Scopes:       "openid profile",
		IsPublic:     boolPtr(false),
		PKCERequired: boolPtr(true),
		Enabled:      boolPtr(true),
	}

	v := clientView(cl)
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Error("管理端视图的序列化结果中不应出现 client_secret 明文")
	}

	if !v.HasSecret {
		t.Error("配置了 secret 的客户端 has_secret 应为 true")
	}
	if v.ClientID != "some-client" || v.ClientName != "某客户端" {
		t.Error("基础字段应正确透传")
	}
	if v.ID != 1 {
		t.Errorf("ID = %d, 期望 1", v.ID)
	}
	if len(v.RedirectURIs) != 1 || v.RedirectURIs[0] != "http://127.0.0.1:8081/oauth/callback" {
		t.Errorf("redirect_uris 应被拆分为切片, got=%v", v.RedirectURIs)
	}
	if len(v.Scopes) != 2 {
		t.Errorf("scopes 应被拆分为 2 项, got=%v", v.Scopes)
	}
	if v.IsPublic || !v.PKCERequired || !v.Enabled {
		t.Errorf("开关字段透传错误: %+v", v)
	}

	// 公共客户端没有 secret
	pub := cl
	pub.ClientSecret = ""
	if clientView(pub).HasSecret {
		t.Error("无 secret 的客户端 has_secret 应为 false")
	}
}

// TestClientView_EmptyListsMarshalAsArray 空列表必须序列化成 [] 而不是 null。
//
// 前端对列表做 .length/.map，null 会直接抛错（迁移前的 gs-ac 前端
// 就因为 list:null 白屏过一次）。
func TestClientView_EmptyListsMarshalAsArray(t *testing.T) {
	v := clientView(entity.OAuthClient{ClientID: "c"})
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	for _, k := range []string{"redirect_uris", "scopes", "post_logout_uris"} {
		if string(back[k]) != "[]" {
			t.Errorf("%s = %s, 期望 []", k, string(back[k]))
		}
	}
}

// TestTokenRows_MappingFields 令牌行映射：脱敏 + 派生 sub
func TestTokenRows_MappingFields(t *testing.T) {
	rows := []logicadmin.RefreshRow{
		{
			Id:       7,
			Token:    "abcdefgh••••••••",
			UserID:   42,
			Username: "test",
			ClientID: "gs-ac",
			Scope:    "openid profile",
		},
	}
	out := tokenRows(rows)
	if len(out) != 1 {
		t.Fatalf("长度 = %d", len(out))
	}
	got := out[0]
	if got.UserSub != "42" {
		t.Errorf("user_sub = %q, 期望 \"42\"（与 id_token 的 sub 必须一致）", got.UserSub)
	}
	if got.ID != 7 || got.UserID != 42 || got.Username != "test" || got.ClientID != "gs-ac" {
		t.Errorf("字段透传错误: %+v", got)
	}
	if !strings.Contains(got.Token, "•") {
		t.Errorf("token 应已脱敏: %q", got.Token)
	}
}

// TestTokenRows_EmptyIsArray 空结果也必须是 []（前端直接 .length）
func TestTokenRows_EmptyIsArray(t *testing.T) {
	raw, err := json.Marshal(tokenRows(nil))
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if string(raw) != "[]" {
		t.Errorf("空令牌列表序列化 = %s, 期望 []", string(raw))
	}
}

// TestAdminErrorRes_Shape 失败响应的字段形状（无 code，message 可选）
func TestAdminErrorRes_Shape(t *testing.T) {
	raw, err := json.Marshal(v1.AdminErrorRes{Error: "not_found"})
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if !strings.Contains(string(raw), `"error":"not_found"`) {
		t.Errorf("缺少 error 字段: %s", string(raw))
	}
	if strings.Contains(string(raw), `"code"`) {
		t.Errorf("管理接口失败响应不应包含 code 字段: %s", string(raw))
	}
}

func boolPtr(b bool) *bool { return &b }
