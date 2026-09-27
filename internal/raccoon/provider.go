// Package raccoon 把「办公小浣熊」(xiaohuanxiong.com) 反向代理移植进本网关，
// 作为独立子网关挂在 /raccoon/v1/* 前缀下，与 CodeBuddy 主链路完全隔离。
//
// 移植来源：桌面「小浣熊」APK（dev.raccoon2api）的 RaccoonProvider / Router / AccountStore。
// 上游是标准 OpenAI 兼容形态（chat/completions SSE + model_catalog + JWT Bearer + refresh），
// 因此可直接复用本仓库 internal/upstream 的 SSE 聚合/透传逻辑。
package raccoon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// 上游基础域与端点（对齐 APK 内 RaccoonProvider 常量）。
const (
	LLMBase    = "https://xiaohuanxiong.com/api/web/llm/v2"
	AuthBase   = "https://xiaohuanxiong.com/api/web/auth/v1"
	MainOrigin = "https://xiaohuanxiong.com"

	appName        = "办公小浣熊客户端"
	callbackPrefix = "office-raccoon://auth/callback"
	codeExpired    = 200035

	authTimeout    = 30 * time.Second
	catalogTimeout = 10 * time.Second
)

// Provider 无状态上游客户端；base URL 可覆盖便于测试。
type Provider struct {
	HTTP       *http.Client // 短 RPC（exchange/refresh/catalog）
	ChatHTTP   *http.Client // chat SSE：无总时长上限
	LLMBase    string
	AuthBase   string
	MainOrigin string
}

// NewProvider 生产默认值。
func NewProvider() *Provider {
	tr := &http.Transport{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Provider{
		HTTP:       &http.Client{Timeout: authTimeout, Transport: tr},
		ChatHTTP:   &http.Client{Timeout: 0, Transport: tr},
		LLMBase:    LLMBase,
		AuthBase:   AuthBase,
		MainOrigin: MainOrigin,
	}
}

// ExchangeResult 网页登录换取的凭证。
type ExchangeResult struct {
	AccessToken  string
	RefreshToken string
	OfficeID     string
	OrgName      string
	OrgRole      string
	DisplayName  string
}

// RefreshResult token 刷新结果。
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
}

// UpstreamError 上游业务错误（带 HTTP 状态与可选 upstream code）。
type UpstreamError struct {
	Status int
	Msg    string
	Code   *int64
}

func (e *UpstreamError) Error() string { return e.Msg }

// BuildAuthorizeURL 构造网页登录授权链接（用户在浏览器打开）。
func (p *Provider) BuildAuthorizeURL(state string) string {
	return p.MainOrigin + "/code/authorize?login_source=desktop&appname=" +
		url.QueryEscape(appName) + "&state=" + url.QueryEscape(state)
}

// ParseCallbackCode 从回调 URL 解析 (code, state)。非法返回 ("","",false)。
func ParseCallbackCode(rawURL string) (code, state string, ok bool) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed != callbackPrefix && !strings.HasPrefix(trimmed, callbackPrefix+"?") {
		return "", "", false
	}
	rest := strings.TrimPrefix(trimmed, callbackPrefix)
	rest = strings.TrimPrefix(rest, "?")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	q, err := url.ParseQuery(rest)
	if err != nil {
		return "", "", false
	}
	code = strings.TrimSpace(q.Get("code"))
	state = strings.TrimSpace(q.Get("state"))
	if code == "" || len(code) > 8192 || state == "" || len(state) > 512 {
		return "", "", false
	}
	return code, state, true
}

// rawResponse 内部 JSON RPC 响应。
type rawResponse struct {
	status  int
	payload map[string]any
}

func (p *Provider) requestJSON(ctx context.Context, method, urlStr string, body []byte, headers map[string]string) (rawResponse, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, rdr)
	if err != nil {
		return rawResponse{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return rawResponse{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var payload map[string]any
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &payload) // 非 JSON 时 payload 为 nil，交由调用方判断
	}
	return rawResponse{status: resp.StatusCode, payload: payload}, nil
}

// ExchangeCode 用授权码换取凭证。
func (p *Provider) ExchangeCode(ctx context.Context, code string) (*ExchangeResult, error) {
	body, _ := json.Marshal(map[string]string{"authorization_code": code})
	resp, err := p.requestJSON(ctx, http.MethodPost, p.AuthBase+"/login_with_authorization_code", body,
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, &UpstreamError{Status: 502, Msg: "连接小浣熊登录接口失败: " + err.Error()}
	}
	payload := resp.payload
	if payload == nil {
		payload = map[string]any{}
	}
	upCode, hasCode := optInt64(payload, "code")
	if hasCode && upCode == codeExpired {
		c := upCode
		return nil, &UpstreamError{Status: 400, Msg: "授权码已失效，请重新发起网页登录", Code: &c}
	}
	if resp.status < 200 || resp.status >= 300 {
		msg := firstNonEmpty(textOf(payload, "message"), textOf(payload, "msg"),
			fmt.Sprintf("网页登录换取凭证失败（HTTP %d）", resp.status))
		if msg == "internal_server_error" {
			msg = "登录服务异常，请稍后重试"
		}
		status := 502
		if resp.status >= 400 && resp.status < 500 {
			status = resp.status
		}
		return nil, &UpstreamError{Status: status, Msg: msg}
	}
	data := objOf(payload, "data")
	accessToken := textOf(data, "access_token")
	refreshToken := textOf(data, "refresh_token")
	if accessToken == "" || refreshToken == "" {
		return nil, &UpstreamError{Status: 502, Msg: fmt.Sprintf("网页登录换取凭证失败（HTTP %d）", resp.status)}
	}
	return &ExchangeResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		OfficeID:     strings.TrimSpace(textOf(data, "office_identity")),
		OrgName:      strings.TrimSpace(textOf(data, "office_org_name")),
		OrgRole:      strings.TrimSpace(textOf(data, "office_org_role")),
		DisplayName:  displayNameOf(data),
	}, nil
}

// LoginWithPassword 手机号 + 密码直登（纯 API，无需 App WebView）。
// phone/password 按上游 Zr 算法 AES-128-CFB 加密后传输；成功返回凭证。
// 触发验证码时上游返回业务错误，调用方应回退到网页登录 + 粘贴 token。
//
// nationCode 无「+」号，默认大陆 "86"。
func (p *Provider) LoginWithPassword(ctx context.Context, nationCode, phone, password string) (*ExchangeResult, error) {
	if nationCode == "" {
		nationCode = "86"
	}
	encPhone, err := encryptField(phone)
	if err != nil {
		return nil, &UpstreamError{Status: 500, Msg: "手机号加密失败: " + err.Error()}
	}
	encPwd, err := encryptField(password)
	if err != nil {
		return nil, &UpstreamError{Status: 500, Msg: "密码加密失败: " + err.Error()}
	}
	body, _ := json.Marshal(map[string]string{
		"nation_code": nationCode,
		"phone":       encPhone,
		"password":    encPwd,
	})
	resp, err := p.requestJSON(ctx, http.MethodPost, p.AuthBase+"/login_with_password", body,
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, &UpstreamError{Status: 502, Msg: "连接小浣熊登录接口失败: " + err.Error()}
	}
	payload := resp.payload
	if payload == nil {
		payload = map[string]any{}
	}
	if resp.status < 200 || resp.status >= 300 {
		msg := firstNonEmpty(textOf(payload, "message"), textOf(payload, "msg"),
			fmt.Sprintf("登录失败（HTTP %d）", resp.status))
		// 常见业务码：密码错误 / 需验证码 / 参数错误，透传原始文案便于排查。
		if detail := textOf(payload, "details"); detail != "" {
			msg = msg + "（" + detail + "）"
		}
		status := 502
		if resp.status >= 400 && resp.status < 500 {
			status = resp.status
		}
		return nil, &UpstreamError{Status: status, Msg: "小浣熊登录失败: " + msg}
	}
	data := objOf(payload, "data")
	accessToken := textOf(data, "access_token")
	refreshToken := textOf(data, "refresh_token")
	if accessToken == "" || refreshToken == "" {
		return nil, &UpstreamError{Status: 502, Msg: "登录成功但未返回 token（可能需要验证码，请改用网页登录）"}
	}
	return &ExchangeResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		OfficeID:     strings.TrimSpace(textOf(data, "office_identity")),
		OrgName:      strings.TrimSpace(textOf(data, "office_org_name")),
		OrgRole:      strings.TrimSpace(textOf(data, "office_org_role")),
		DisplayName:  displayNameOf(data),
	}, nil
}

// Refresh 刷新 token。
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	resp, err := p.requestJSON(ctx, http.MethodPost, p.AuthBase+"/refresh", body,
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, &UpstreamError{Status: 502, Msg: "连接小浣熊刷新接口失败: " + err.Error()}
	}
	payload := resp.payload
	if payload == nil {
		payload = map[string]any{}
	}
	if resp.status < 200 || resp.status >= 300 {
		msg := firstNonEmpty(textOf(payload, "message"), textOf(payload, "msg"), "服务器未返回错误说明")
		status := 502
		if resp.status == 401 {
			status = 401
		}
		return nil, &UpstreamError{Status: status, Msg: fmt.Sprintf("小浣熊刷新接口失败（HTTP %d）: %s", resp.status, msg)}
	}
	data := objOf(payload, "data")
	accessToken := textOf(data, "access_token")
	if accessToken == "" {
		msg := firstNonEmpty(textOf(payload, "message"), textOf(payload, "msg"), "服务器未返回新 token")
		return nil, &UpstreamError{Status: 401, Msg: "小浣熊 token 刷新失败: " + msg}
	}
	next := textOf(data, "refresh_token")
	if next == "" {
		next = refreshToken
	}
	return &RefreshResult{AccessToken: accessToken, RefreshToken: next}, nil
}

// OpenChat 发起 chat/completions（强制 stream）。返回响应体供调用方按 SSE 处理。
// 非传输层失败即返回 resp（调用方检查 StatusCode）；传输失败返回 err。
func (p *Provider) OpenChat(ctx context.Context, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.LLMBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Authorization", "Bearer "+stripBearer(token))
	return p.ChatHTTP.Do(req)
}

// FetchModelCatalog 拉取上游模型目录。
func (p *Provider) FetchModelCatalog(ctx context.Context, token string) ([]ModelInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.LLMBase+"/model_catalog", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+stripBearer(token))
	}
	cctx, cancel := context.WithTimeout(ctx, catalogTimeout)
	defer cancel()
	resp, err := p.HTTP.Do(req.WithContext(cctx))
	if err != nil {
		return nil, &UpstreamError{Status: 502, Msg: "拉取模型目录失败: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &UpstreamError{Status: resp.StatusCode, Msg: fmt.Sprintf("上游返回 HTTP %d", resp.StatusCode)}
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, &UpstreamError{Status: 502, Msg: "模型目录解析失败"}
	}
	return parseCatalog(payload), nil
}

// DescribeError 从上游错误响应体提取可读文案。
func DescribeError(status int, raw []byte) string {
	text := ""
	var payload map[string]any
	if json.Unmarshal(raw, &payload) == nil {
		text = firstNonEmpty(textOf(payload, "message"), textOf(payload, "msg"))
		if text == "" {
			if e := objOf(payload, "error"); e != nil {
				text = textOf(e, "message")
			}
		}
	}
	if text == "" {
		text = strings.TrimSpace(string(raw))
		if text == "" {
			text = "上游错误"
		}
	}
	return fmt.Sprintf("上游返回 %d: %s", status, text)
}

// ---- JWT 与 JSON 辅助 ----

// stripBearer 去掉可能的 "Bearer " 前缀。
func stripBearer(v string) string {
	t := strings.TrimSpace(v)
	if len(t) <= len("bearer") {
		return t
	}
	if strings.EqualFold(t[:len("bearer")], "bearer") {
		rest := t[len("bearer"):]
		if rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			return strings.TrimSpace(rest)
		}
	}
	return t
}

// decodeJWTClaims 解出 JWT payload 段。
func decodeJWTClaims(token string) map[string]any {
	parts := strings.Split(stripBearer(token), ".")
	if len(parts) < 2 || parts[1] == "" {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// 兼容带 padding 的编码
		decoded, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var claims map[string]any
	if json.Unmarshal(decoded, &claims) != nil {
		return nil
	}
	return claims
}

// jwtExpiryUnix 返回 JWT exp（Unix 秒）；无则 0。
func jwtExpiryUnix(token string) int64 {
	claims := decodeJWTClaims(token)
	if claims == nil {
		return 0
	}
	if v, ok := num64(claims["exp"]); ok && v > 0 {
		return int64(v)
	}
	return 0
}

// jwtUserID 从 claims 提取用户标识（sub/id/user_id 优先原样，sid/iss 作十六进制转十进制）。
func jwtUserID(token string) string {
	claims := decodeJWTClaims(token)
	if claims == nil {
		return ""
	}
	for _, k := range []string{"sub", "id", "user_id"} {
		if s := strings.TrimSpace(asText(claims, k)); s != "" {
			return s
		}
	}
	return ""
}

func displayNameOf(obj map[string]any) string {
	for _, k := range []string{"nickname", "nick_name", "user_name", "name", "username", "phone", "mobile"} {
		if s := strings.TrimSpace(asText(obj, k)); s != "" {
			return s
		}
	}
	return ""
}

func asText(obj map[string]any, key string) string { return textOf(obj, key) }

func textOf(obj map[string]any, key string) string {
	if obj == nil {
		return ""
	}
	switch v := obj[key].(type) {
	case string:
		return v
	case float64:
		return strings.TrimSuffix(fmt.Sprintf("%v", v), ".0")
	case bool:
		return fmt.Sprintf("%v", v)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func objOf(obj map[string]any, key string) map[string]any {
	if obj == nil {
		return nil
	}
	if m, ok := obj[key].(map[string]any); ok {
		return m
	}
	return nil
}

func optInt64(obj map[string]any, key string) (int64, bool) {
	if obj == nil {
		return 0, false
	}
	v, ok := obj[key]
	if !ok {
		return 0, false
	}
	if f, ok := num64(v); ok {
		return int64(f), true
	}
	return 0, false
}

func num64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
