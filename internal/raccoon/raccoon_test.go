package raccoon

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(body)
	return header + "." + payload + ".sig"
}

func TestStripBearer(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":   "abc",
		"bearer  xyz":  "xyz",
		"token123":     "token123",
		"BearerNoSpc":  "BearerNoSpc",
		"  Bearer q  ": "q",
	}
	for in, want := range cases {
		if got := stripBearer(in); got != want {
			t.Errorf("stripBearer(%q)=%q want %q", in, got, want)
		}
	}
}

func TestJWTExpiryAndUserID(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	tok := makeJWT(map[string]any{"exp": exp, "sub": "user-42"})
	if got := jwtExpiryUnix(tok); got != exp {
		t.Errorf("expiry=%d want %d", got, exp)
	}
	if got := jwtUserID(tok); got != "user-42" {
		t.Errorf("userID=%q want user-42", got)
	}
	if jwtExpiryUnix("garbage") != 0 {
		t.Error("garbage token should have 0 expiry")
	}
}

func TestParseCallbackCode(t *testing.T) {
	ok := "office-raccoon://auth/callback?code=abc123&state=st-9"
	code, state, valid := ParseCallbackCode(ok)
	if !valid || code != "abc123" || state != "st-9" {
		t.Errorf("parse ok failed: %q %q %v", code, state, valid)
	}
	if _, _, v := ParseCallbackCode("https://evil.com/?code=x&state=y"); v {
		t.Error("non-callback URL should be rejected")
	}
	if _, _, v := ParseCallbackCode("office-raccoon://auth/callback?state=only"); v {
		t.Error("missing code should be rejected")
	}
}

func TestParseCatalog(t *testing.T) {
	payload := map[string]any{
		"data": map[string]any{
			"categories": []any{
				map[string]any{
					"models": []any{
						map[string]any{
							"id":                 "raccoon-x",
							"display_name":       "Raccoon X",
							"tags":               []any{"general", "vision"},
							"context_window":     float64(200000),
							"max_tokens":         float64(64000),
							"billing_multiplier": float64(1.5),
						},
						map[string]any{"id": "raccoon-x"}, // 重复 id 应去重
						map[string]any{"model_name": "raccoon-y", "params": map[string]any{"max_tokens": float64(8000)}},
					},
				},
			},
		},
	}
	models := parseCatalog(payload)
	if len(models) != 2 {
		t.Fatalf("want 2 models, got %d", len(models))
	}
	x := models[0]
	if x.ID != "raccoon-x" || x.Name != "Raccoon X" || !x.SupportsImages {
		t.Errorf("model x unexpected: %+v", x)
	}
	if x.ContextWindow != 200000 || x.MaxTokens != 64000 {
		t.Errorf("model x sizes wrong: %+v", x)
	}
	if x.Credits != "x1.5 credits" {
		t.Errorf("credits=%q want x1.5 credits", x.Credits)
	}
	y := models[1]
	if y.ID != "raccoon-y" || y.MaxTokens != 8000 {
		t.Errorf("model y unexpected (params fallback): %+v", y)
	}
}

func TestFormatMultiplier(t *testing.T) {
	cases := map[float64]string{1: "1", 1.5: "1.5", 0.79: "0.79", 2.0: "2", 0.5: "0.5"}
	for in, want := range cases {
		if got := formatMultiplier(in); got != want {
			t.Errorf("formatMultiplier(%v)=%q want %q", in, got, want)
		}
	}
}

func TestModelToOpenAI(t *testing.T) {
	m := ModelInfo{ID: "m1", Name: "M1", Tags: []string{"a", "b"}, ContextWindow: 1000, MaxTokens: 500, Visible: true}
	out := m.ToOpenAI("raccoon")
	if out["id"] != "m1" || out["owned_by"] != "raccoon" || out["object"] != "model" {
		t.Errorf("openai shape wrong: %+v", out)
	}
	if out["tags"] != "a,b" {
		t.Errorf("tags join wrong: %v", out["tags"])
	}
	if out["maxInputTokens"] != int64(1000) || out["maxOutputTokens"] != int64(500) {
		t.Errorf("token fields wrong: %+v", out)
	}
}

func TestModelRewriter(t *testing.T) {
	in := "data: {\"model\":\"upstream-real\",\"choices\":[]}\n\n" +
		"data: [DONE]\n\n"
	mr := newModelRewriter(strings.NewReader(in), "requested-model")
	out, err := io.ReadAll(mr)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"model":"requested-model"`) {
		t.Errorf("model not rewritten: %s", s)
	}
	if !strings.Contains(s, "[DONE]") {
		t.Errorf("DONE frame lost: %s", s)
	}
	if strings.Contains(s, "upstream-real") {
		t.Errorf("upstream model leaked: %s", s)
	}
}

func TestStoreCRUDAndTokenABA(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/raccoon-accounts.json"
	s := NewStore(file)

	acc := Account{ID: "a1", Name: "acc1", AccessToken: "tok-old", RefreshToken: "r1", Enabled: true}
	if err := s.Add(acc); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Get("a1"); !ok || got.AccessToken != "tok-old" {
		t.Fatalf("get after add failed: %+v %v", got, ok)
	}

	// 条件更新命中（prevAccess 匹配）
	if !s.UpdateTokensIfCurrent("a1", "tok-old", "tok-new", "r2", 0) {
		t.Error("update with matching prevAccess should succeed")
	}
	// 条件更新未命中（prevAccess 已过时）→ 拒绝（ABA 防护）
	if s.UpdateTokensIfCurrent("a1", "tok-old", "tok-evil", "r3", 0) {
		t.Error("stale prevAccess must be rejected")
	}
	got, _ := s.Get("a1")
	if got.AccessToken != "tok-new" || got.RefreshToken != "r2" {
		t.Errorf("token state wrong after ABA: %+v", got)
	}

	// 持久化验证：新建 Store 从磁盘恢复
	s2 := NewStore(file)
	if got, ok := s2.Get("a1"); !ok || got.AccessToken != "tok-new" {
		t.Errorf("reload failed: %+v %v", got, ok)
	}

	if err := s.Remove("a1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("a1"); ok {
		t.Error("account should be removed")
	}
}

// fakeUpstream 起一个假的小浣熊上游用于端到端 chat 测试。
func TestGatewayChatEndToEnd(t *testing.T) {
	// 上游：/chat/completions 返回 SSE；model 字段为上游内部名。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer valid-token" {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"message":"unauthorized"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"model\":\"raccoon-internal\",\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"你好\"}}]}\n\n")
		_, _ = io.WriteString(w, "data: {\"id\":\"c1\",\"model\":\"raccoon-internal\",\"choices\":[{\"delta\":{\"content\":\"世界\"},\"finish_reason\":\"stop\"}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	prov := NewProvider()
	prov.LLMBase = srv.URL
	prov.AuthBase = srv.URL

	store := NewStore(t.TempDir() + "/acc.json")
	_ = store.Add(Account{ID: "a1", Name: "acc1", AccessToken: "valid-token", RefreshToken: "r1", Enabled: true})

	gw := NewGateway(prov, store, func() string { return "" })
	mux := http.NewServeMux()
	gw.Register(mux)

	// 非流式请求
	req := httptest.NewRequest("POST", "/raccoon/v1/chat/completions",
		strings.NewReader(`{"model":"raccoon-8c4485","messages":[{"role":"user","content":"hi"}]}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("resp not JSON: %v (%s)", err, rec.Body.String())
	}
	if resp["model"] != "raccoon-8c4485" {
		t.Errorf("model not rewritten to requested: %v", resp["model"])
	}
	choices, _ := resp["choices"].([]any)
	if len(choices) == 0 {
		t.Fatal("no choices in aggregated response")
	}
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "你好世界" {
		t.Errorf("content aggregate wrong: %v", msg["content"])
	}
}

func TestGatewayModelsFallback(t *testing.T) {
	// 上游不可用 → models 回退到内置 fallback。
	prov := NewProvider()
	prov.LLMBase = "http://127.0.0.1:0" // 无效端口
	prov.HTTP = &http.Client{Timeout: 200 * time.Millisecond}
	store := NewStore(t.TempDir() + "/acc.json")
	gw := NewGateway(prov, store, func() string { return "" })
	mux := http.NewServeMux()
	gw.Register(mux)

	req := httptest.NewRequest("GET", "/raccoon/v1/models", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	data, _ := resp["data"].([]any)
	if len(data) != len(FallbackModels()) {
		t.Errorf("fallback models count=%d want %d", len(data), len(FallbackModels()))
	}
}

func TestGatewayAuth(t *testing.T) {
	store := NewStore(t.TempDir() + "/acc.json")
	gw := NewGateway(NewProvider(), store, func() string { return "secret" })
	mux := http.NewServeMux()
	gw.Register(mux)

	// 无 key → 401
	req := httptest.NewRequest("GET", "/raccoon/v1/models", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Errorf("missing key should be 401, got %d", rec.Code)
	}
	// 正确 key → 200
	req = httptest.NewRequest("GET", "/raccoon/v1/models", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("valid key should be 200, got %d", rec.Code)
	}
}

func TestExchangeAndRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/login_with_authorization_code"):
			_, _ = io.WriteString(w, `{"code":0,"data":{"access_token":"at","refresh_token":"rt","office_org_name":"Org","nickname":"Nick"}}`)
		case strings.HasSuffix(r.URL.Path, "/refresh"):
			_, _ = io.WriteString(w, `{"code":0,"data":{"access_token":"at2","refresh_token":"rt2"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	prov := NewProvider()
	prov.AuthBase = srv.URL

	ex, err := prov.ExchangeCode(context.Background(), "code123")
	if err != nil {
		t.Fatal(err)
	}
	if ex.AccessToken != "at" || ex.RefreshToken != "rt" || ex.OrgName != "Org" || ex.DisplayName != "Nick" {
		t.Errorf("exchange result wrong: %+v", ex)
	}
	rf, err := prov.Refresh(context.Background(), "rt")
	if err != nil {
		t.Fatal(err)
	}
	if rf.AccessToken != "at2" || rf.RefreshToken != "rt2" {
		t.Errorf("refresh result wrong: %+v", rf)
	}
}

// TestConcurrentRefreshSingleFlight 验证单飞刷新在多等待者下都拿到同一结果、
// 且上游只被调用一次（code-reviewer 发现 #1 的回归测试）。
func TestConcurrentRefreshSingleFlight(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/refresh") {
			atomic.AddInt32(&calls, 1)
			time.Sleep(30 * time.Millisecond) // 拉长窗口，制造多等待者
			_, _ = io.WriteString(w, `{"code":0,"data":{"access_token":"fresh","refresh_token":"r2"}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	prov := NewProvider()
	prov.AuthBase = srv.URL
	store := NewStore(t.TempDir() + "/acc.json")
	_ = store.Add(Account{ID: "a1", Name: "n", AccessToken: "old", RefreshToken: "r1", Enabled: true})
	gw := NewGateway(prov, store, func() string { return "" })

	const n = 20
	results := make([]string, n)
	var wg sync.WaitGroup
	acc, _ := store.Get("a1")
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = gw.refreshAccount(context.Background(), acc, idx%2 == 0)
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		if r != "fresh" {
			t.Errorf("waiter %d got %q, want fresh (lost broadcast?)", i, r)
		}
	}
	if c := atomic.LoadInt32(&calls); c != 1 {
		t.Errorf("upstream refresh called %d times, want exactly 1", c)
	}
}

// TestEncryptField 验证 AES-128-CFB 加密可被同密钥解回（round-trip），
// 且输出为 base64(iv||ct)、iv 每次随机（对齐上游 Zr 算法）。
func TestEncryptField(t *testing.T) {
	plain := "19330528297"
	enc1, err := encryptField(plain)
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := encryptField(plain)
	if err != nil {
		t.Fatal(err)
	}
	if enc1 == enc2 {
		t.Error("两次加密应因随机 IV 不同而不同")
	}
	raw, err := base64.StdEncoding.DecodeString(enc1)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < aes.BlockSize {
		t.Fatalf("密文过短: %d", len(raw))
	}
	iv, ct := raw[:aes.BlockSize], raw[aes.BlockSize:]
	if len(ct) != len(plain) {
		t.Errorf("NoPadding 下密文长度应等于明文: got %d want %d", len(ct), len(plain))
	}
	block, _ := aes.NewCipher(raccoonAESKey)
	dec := make([]byte, len(ct))
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(dec, ct)
	if string(dec) != plain {
		t.Errorf("解密不还原: got %q want %q", dec, plain)
	}
}

// TestLoginWithPassword 用假上游验证密码登录链路：
// phone/password 被加密（非明文）、nation_code 默认 86、成功解出 token。
func TestLoginWithPassword(t *testing.T) {
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/login_with_password") {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = io.WriteString(w, `{"code":0,"data":{"access_token":"AT","refresh_token":"RT","nickname":"Ras"}}`)
	}))
	defer srv.Close()
	prov := NewProvider()
	prov.AuthBase = srv.URL
	ex, err := prov.LoginWithPassword(context.Background(), "", "19330528297", "secret!")
	if err != nil {
		t.Fatal(err)
	}
	if ex.AccessToken != "AT" || ex.RefreshToken != "RT" || ex.DisplayName != "Ras" {
		t.Errorf("login result wrong: %+v", ex)
	}
	if gotBody["nation_code"] != "86" {
		t.Errorf("nation_code 默认应为 86, got %q", gotBody["nation_code"])
	}
	if gotBody["phone"] == "19330528297" || gotBody["phone"] == "" {
		t.Errorf("phone 应被加密而非明文/空: %q", gotBody["phone"])
	}
	if gotBody["password"] == "secret!" || gotBody["password"] == "" {
		t.Errorf("password 应被加密而非明文/空: %q", gotBody["password"])
	}
}

// TestLoginWithPasswordCaptcha 验证上游要验证码时返回可读错误。
func TestLoginWithPasswordCaptcha(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = io.WriteString(w, `{"code":100010,"message":"need_captcha","details":"captcha required"}`)
	}))
	defer srv.Close()
	prov := NewProvider()
	prov.AuthBase = srv.URL
	_, err := prov.LoginWithPassword(context.Background(), "86", "13800000000", "x")
	if err == nil {
		t.Fatal("需验证码时应返回错误")
	}
	if !strings.Contains(err.Error(), "captcha") && !strings.Contains(err.Error(), "need_captcha") {
		t.Errorf("错误应透传验证码文案: %v", err)
	}
}

// TestGatewayLoginWithToken 验证 cookie/token 兜底登录：合法 JWT 落号、非法 JWT 拒绝。
func TestGatewayLoginWithToken(t *testing.T) {
	store := NewStore(t.TempDir() + "/acc.json")
	gw := NewGateway(NewProvider(), store, func() string { return "" })

	at := makeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "sub": "u1", "name": "Ras"})
	acc, err := gw.LoginWithToken("Bearer "+at, "rt-xyz")
	if err != nil {
		t.Fatal(err)
	}
	if acc.Name != "Ras" || acc.UserID != "u1" || acc.RefreshToken != "rt-xyz" {
		t.Errorf("token login result wrong: %+v", acc)
	}
	if acc.ExpiresAt <= 0 {
		t.Error("应从 JWT exp 解出过期时间")
	}
	// 落盘可查
	if _, ok := store.Get(acc.ID); !ok {
		t.Error("账号应已落盘")
	}
	// 非法 token 拒绝
	if _, err := gw.LoginWithToken("not-a-jwt", ""); err == nil {
		t.Error("非 JWT 的 token 应被拒绝")
	}
	if _, err := gw.LoginWithToken("", ""); err == nil {
		t.Error("空 token 应被拒绝")
	}
}

// TestDailyCheckin 用假上游验证签到：发放/已领取两种响应。
func TestDailyCheckin(t *testing.T) {
	granted := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/points/v1/bills") {
			// 当日一笔 daily_grant 30 分。
			today := timeNowDate()
			_, _ = io.WriteString(w, `{"code":0,"data":{"items":[{"biz_type":"daily_grant","points":30,"created_at":"`+today+`T09:00:00Z"}]}}`)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/login/points/grant") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Client-Platform") != "desktop-windows" {
			t.Errorf("缺少桌面指纹头 X-Client-Platform")
		}
		if granted {
			_, _ = io.WriteString(w, `{"code":0,"data":{"granted":true,"popup":null}}`)
		} else {
			_, _ = io.WriteString(w, `{"code":0,"data":{"granted":false}}`)
		}
	}))
	defer srv.Close()
	prov := NewProvider()
	prov.MainOrigin = srv.URL
	res, err := prov.DailyCheckin(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Granted || res.Points != 30 {
		t.Errorf("首次签到应发放 30 分: %+v", res)
	}
	granted = false
	res2, err := prov.DailyCheckin(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if res2.Granted {
		t.Errorf("重复签到应为已领取: %+v", res2)
	}
}

// TestQueryBalance 验证积分余额解析。
func TestQueryBalance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/points/v1/balance") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"code":0,"data":{"available_points":128,"daily_points":30,"reward_points":98}}`)
	}))
	defer srv.Close()
	prov := NewProvider()
	prov.MainOrigin = srv.URL
	b, err := prov.QueryBalance(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if b.Available != 128 || b.Daily != 30 || b.Reward != 98 {
		t.Errorf("余额解析错误: %+v", b)
	}
}

// TestCheckinAll 验证批量签到对多账号执行且返回逐账号结果。
func TestCheckinAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"code":0,"data":{"granted":true,"points":30}}`)
	}))
	defer srv.Close()
	prov := NewProvider()
	prov.MainOrigin = srv.URL
	store := NewStore(t.TempDir() + "/acc.json")
	at := makeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "sub": "u"})
	_ = store.Add(Account{ID: "a1", Name: "n1", AccessToken: at, RefreshToken: "r", Enabled: true})
	_ = store.Add(Account{ID: "a2", Name: "n2", AccessToken: at, RefreshToken: "r", Enabled: true})
	gw := NewGateway(prov, store, func() string { return "" })
	reps := gw.CheckinAll(context.Background())
	if len(reps) != 2 {
		t.Fatalf("应返回 2 个账号结果, got %d", len(reps))
	}
	for _, r := range reps {
		if !r.OK {
			t.Errorf("账号 %s 签到应成功: %s", r.Name, r.Message)
		}
	}
}
