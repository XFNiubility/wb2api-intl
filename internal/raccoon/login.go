// login.go 小浣熊面板登录支持：生成授权链接 + 校验回调 code/state 换凭证落号。
//
// 与 CodeBuddy 的设备授权流不同，小浣熊授权后浏览器跳转到自定义 scheme
// office-raccoon://auth/callback?code=...&state=...（无法被网关自动接收），
// 因此采用两步式：StartLogin 返回授权 URL + state（进程内暂存防 CSRF），
// 用户登录后把回调 URL 粘回来交 ExchangeLogin 解析 code → 换凭证 → 落号。
package raccoon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// loginTTL 授权会话有效期：超时的 state 视为失效。
const loginTTL = 10 * time.Minute

// pendingLogin 进行中的授权会话。
type pendingLogin struct {
	created time.Time
}

// loginState 面板登录会话表（state → 会话），进程内、常驻进程容量天然有界。
type loginStore struct {
	mu       sync.Mutex
	sessions map[string]pendingLogin
}

func newLoginStore() *loginStore {
	return &loginStore{sessions: map[string]pendingLogin{}}
}

func (l *loginStore) put(state string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// 顺手回收过期会话。
	for s, p := range l.sessions {
		if time.Since(p.created) > loginTTL {
			delete(l.sessions, s)
		}
	}
	l.sessions[state] = pendingLogin{created: time.Now()}
}

// consume 校验并消费 state：存在且未过期返回 true 并删除。
func (l *loginStore) consume(state string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, ok := l.sessions[state]
	if !ok || time.Since(p.created) > loginTTL {
		delete(l.sessions, state)
		return false
	}
	delete(l.sessions, state)
	return true
}

// StartLogin 生成授权链接与 state（面板「添加账号-办公小浣熊」用）。
func (g *Gateway) StartLogin() (authURL, state string) {
	state = randHex(16)
	g.loginStore.put(state)
	return g.provider.BuildAuthorizeURL(state), state
}

// ExchangeLogin 解析回调 URL 的 code+state，校验 state 后换取凭证并落号（网页授权码流）。
// 返回落盘账号的展示信息。state 未知/过期返回错误（防重放）。
func (g *Gateway) ExchangeLogin(ctx context.Context, callbackURL string) (Account, error) {
	code, state, ok := ParseCallbackCode(callbackURL)
	if !ok {
		return Account{}, fmt.Errorf("回调 URL 非法：无法解析 code/state")
	}
	if !g.loginStore.consume(state) {
		return Account{}, fmt.Errorf("state 未知或已过期，请重新发起登录")
	}
	ex, err := g.provider.ExchangeCode(ctx, code)
	if err != nil {
		return Account{}, err
	}
	return g.persistCredential(ex)
}

// LoginWithPassword 手机号 + 密码直登并落号（纯 API，推荐的面板登录方式）。
// 触发验证码时返回错误，调用方应提示改用网页登录 + 粘贴 token。
func (g *Gateway) LoginWithPassword(ctx context.Context, nationCode, phone, password string) (Account, error) {
	ex, err := g.provider.LoginWithPassword(ctx, nationCode, phone, password)
	if err != nil {
		return Account{}, err
	}
	return g.persistCredential(ex)
}

// LoginWithToken 用已有的 access/refresh token 直接落号（滑块兜底：从浏览器
// cookie raccoon_token / raccoon_refresh_token 复制而来）。纯本地校验 JWT，不打上游。
// refreshToken 可为空（仅 access 也能用到过期为止，但无法自动续期）。
func (g *Gateway) LoginWithToken(accessToken, refreshToken string) (Account, error) {
	at := stripBearer(strings.TrimSpace(accessToken))
	if at == "" {
		return Account{}, fmt.Errorf("access_token 不能为空")
	}
	claims := decodeJWTClaims(at)
	if claims == nil {
		return Account{}, fmt.Errorf("access_token 不是有效 JWT（请从浏览器 cookie 的 raccoon_token 复制完整值）")
	}
	ex := &ExchangeResult{
		AccessToken:  at,
		RefreshToken: stripBearer(strings.TrimSpace(refreshToken)),
		DisplayName:  strings.TrimSpace(asText(claims, "name")),
	}
	return g.persistCredential(ex)
}

// persistCredential 把换取到的凭证归一化为 Account 并落盘（多条登录路径共用）。
func (g *Gateway) persistCredential(ex *ExchangeResult) (Account, error) {
	id := randHex(16)
	name := ex.DisplayName
	if name == "" {
		name = "raccoon-" + id[:6]
	}
	acc := Account{
		ID:           id,
		Name:         name,
		AccessToken:  ex.AccessToken,
		RefreshToken: ex.RefreshToken,
		OrgName:      ex.OrgName,
		OfficeRole:   ex.OrgRole,
		Enabled:      true,
		CreatedAt:    time.Now().UnixMilli(),
	}
	if uid := jwtUserID(ex.AccessToken); uid != "" {
		acc.UserID = uid
	}
	if exp := jwtExpiryUnix(ex.AccessToken); exp > 0 {
		acc.ExpiresAt = exp * 1000
	}
	if err := g.store.Add(acc); err != nil {
		return Account{}, fmt.Errorf("落盘账号失败: %w", err)
	}
	return acc, nil
}

// Accounts 返回账号池脱敏快照（面板列表用）。
func (g *Gateway) Accounts() []Account {
	list := g.store.List()
	for i := range list {
		list[i].AccessToken = list[i].TokenTail() // 脱敏：只留末 4 位
		list[i].RefreshToken = ""
	}
	return list
}

// RemoveAccount 删除账号（面板运维用）。
func (g *Gateway) RemoveAccount(id string) error { return g.store.Remove(id) }

// SetAccountEnabled 启停账号（面板运维用）。
func (g *Gateway) SetAccountEnabled(id string, enabled bool) error {
	return g.store.SetEnabled(id, enabled)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
