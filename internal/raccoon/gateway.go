// gateway.go 小浣熊子网关：OpenAI 兼容路由 + 账号轮换 + 冷却 + token 刷新。
// 移植自 APK dev.raccoon2api.gateway.Router，转发链路复用 internal/upstream 的
// SSE 聚合/透传（Aggregate/Stream），与 CodeBuddy 主链路完全隔离。
package raccoon

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/upstream"
)

// cooldownMS 429 限流后的冷却时长（对齐 APK COOLDOWN_MS=600000）。
const cooldownDuration = 10 * time.Minute

// Gateway 小浣熊 HTTP 子网关。挂在 /raccoon/v1/* 前缀下。
type Gateway struct {
	provider *Provider
	store    *Store
	apiKey   func() string // 网关鉴权密钥（空 = 放行）

	mu        sync.Mutex
	cooldowns map[string]time.Time // accountID -> until
	// flights 单飞刷新：同账号并发刷新只发一次网络请求，结果经 waiter.done 广播。
	flights map[string]*refreshWaiter

	catMu   sync.Mutex
	catalog []ModelInfo
	catAt   time.Time

	loginStore *loginStore
}

// catalogTTL 模型目录缓存有效期（对齐 APK CATALOG_TTL_MS=600000）。
const catalogTTL = 10 * time.Minute

// NewGateway 构建子网关。apiKeyFn 返回当前生效的网关密钥（可热改）。
func NewGateway(provider *Provider, store *Store, apiKeyFn func() string) *Gateway {
	if apiKeyFn == nil {
		apiKeyFn = func() string { return "" }
	}
	return &Gateway{
		provider:   provider,
		store:      store,
		apiKey:     apiKeyFn,
		cooldowns:  map[string]time.Time{},
		flights:    map[string]*refreshWaiter{},
		loginStore: newLoginStore(),
	}
}

// Routes 把子网关端点注册到给定 mux（调用方负责前缀）。
// 注册的相对路径：POST /raccoon/v1/chat/completions、GET /raccoon/v1/models、GET /raccoon/healthz。
func (g *Gateway) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /raccoon/v1/chat/completions", g.withAuth(g.chat))
	mux.HandleFunc("GET /raccoon/v1/models", g.withAuth(g.models))
	mux.HandleFunc("GET /raccoon/healthz", g.health)
}

func (g *Gateway) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := g.apiKey()
		if key != "" {
			got := r.Header.Get("Authorization")
			if len(got) > 7 && (got[:7] == "Bearer " || got[:7] == "bearer ") {
				got = got[7:]
			}
			if got != key {
				writeError(w, http.StatusUnauthorized, "网关 API Key 校验失败", "authentication_error")
				return
			}
		}
		next(w, r)
	}
}

func (g *Gateway) health(w http.ResponseWriter, r *http.Request) {
	g.catMu.Lock()
	n := len(g.catalog)
	g.catMu.Unlock()
	if n == 0 {
		n = len(FallbackModels())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"service":  "raccoon2api",
		"provider": "raccoon",
		"accounts": len(g.store.List()),
		"models":   n,
	})
}

func (g *Gateway) models(w http.ResponseWriter, r *http.Request) {
	refreshed := g.ensureCatalogFresh(r.Context())
	g.catMu.Lock()
	list := g.catalog
	hasCache := len(g.catalog) > 0
	g.catMu.Unlock()
	if list == nil {
		list = FallbackModels()
	}
	data := make([]map[string]any, 0, len(list))
	for _, m := range list {
		if m.Visible {
			data = append(data, m.ToOpenAI("raccoon"))
		}
	}
	source := "fallback"
	if refreshed {
		source = "remote"
	} else if hasCache {
		source = "cached"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
		"meta":   map[string]any{"source": source, "count": len(data)},
	})
}

// ensureCatalogFresh 目录过期则用任一可用账号刷新一次。返回是否本次刷新成功。
func (g *Gateway) ensureCatalogFresh(ctx context.Context) bool {
	g.catMu.Lock()
	fresh := g.catalog != nil && time.Since(g.catAt) < catalogTTL
	g.catMu.Unlock()
	if fresh {
		return false
	}
	token := ""
	for _, a := range g.store.Enabled() {
		if t := g.ensureToken(ctx, a); t != "" {
			token = t
			break
		}
	}
	models, err := g.provider.FetchModelCatalog(ctx, token)
	if err != nil || len(models) == 0 {
		return false
	}
	g.catMu.Lock()
	g.catalog = models
	g.catAt = time.Now()
	g.catMu.Unlock()
	return true
}

func (g *Gateway) chat(w http.ResponseWriter, r *http.Request) {
	body, err := readLimited(r, 8<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), "invalid_request")
		return
	}
	var req map[string]any
	if json.Unmarshal(body, &req) != nil {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON", "invalid_request")
		return
	}
	requestedModel, _ := req["model"].(string)
	if requestedModel == "" {
		writeError(w, http.StatusBadRequest, "缺少 model 字段", "invalid_request")
		return
	}
	if _, ok := req["messages"]; !ok {
		writeError(w, http.StatusBadRequest, "缺少 messages 字段", "invalid_request")
		return
	}
	stream := false
	if b, ok := req["stream"].(bool); ok && b {
		stream = true
	}
	// 出站强制 stream:true（对齐 APK：本地按需聚合为非流式）。
	req["stream"] = true
	outBody, _ := json.Marshal(req)

	var lastErr *UpstreamError
	for _, acct := range g.candidates() {
		token := g.ensureToken(r.Context(), acct)
		if token == "" {
			lastErr = &UpstreamError{Status: 401, Msg: "账号 " + acct.Name + " 没有可用凭证"}
			continue
		}
		resp, terr := g.provider.OpenChat(r.Context(), token, outBody)
		if terr != nil {
			log.Printf("raccoon chat uid=%s: transport error: %v", shortID(acct.ID), terr)
			lastErr = &UpstreamError{Status: 502, Msg: "连接小浣熊上游失败: " + terr.Error()}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			raw, _ := readAllLimited(resp.Body, 1<<20)
			resp.Body.Close()
			msg := DescribeError(resp.StatusCode, raw)
			lastErr = &UpstreamError{Status: resp.StatusCode, Msg: msg}
			if resp.StatusCode == 401 {
				// 强制刷新一次后重试同账号。
				log.Printf("raccoon chat uid=%s: 401, force refresh & retry", shortID(acct.ID))
				if g.refreshAccount(r.Context(), acct, true) != "" {
					if retryed := g.retrySingle(r.Context(), acct, outBody, requestedModel, stream, w); retryed {
						return
					}
				}
				continue
			}
			if resp.StatusCode == 429 {
				g.setCooldown(acct.ID)
				log.Printf("raccoon chat uid=%s: 429 限流，冷却 10 分钟，降级下一个", shortID(acct.ID))
			} else {
				log.Printf("raccoon chat uid=%s: 上游 HTTP %d，尝试下一个候选", shortID(acct.ID), resp.StatusCode)
			}
			continue
		}
		// 命中：转发。
		log.Printf("raccoon chat uid=%s: 命中，开始转发", shortID(acct.ID))
		if stream {
			_ = upstream.Stream(w, newModelRewriter(resp.Body, requestedModel))
			resp.Body.Close()
			return
		}
		agg, aerr := upstream.Aggregate(newModelRewriter(resp.Body, requestedModel))
		resp.Body.Close()
		if aerr != nil {
			writeError(w, http.StatusBadGateway, "读取上游流失败: "+aerr.Error(), "upstream_parse")
			return
		}
		if _, ok := agg["model"]; ok {
			agg["model"] = requestedModel
		}
		writeJSON(w, http.StatusOK, agg)
		return
	}
	if lastErr == nil {
		writeError(w, http.StatusServiceUnavailable, "没有可用的账号，请先添加小浣熊账号", "no_account")
		return
	}
	status := lastErr.Status
	if status < 400 || status > 599 {
		status = 502
	}
	writeError(w, status, lastErr.Msg, "upstream_error")
}

// retrySingle 401 强刷后重试同账号一次；成功写响应并返回 true。
func (g *Gateway) retrySingle(ctx context.Context, acct Account, outBody []byte, requestedModel string, stream bool, w http.ResponseWriter) bool {
	fresh, ok := g.store.Get(acct.ID)
	if !ok {
		return false
	}
	token := fresh.AccessToken
	if token == "" {
		return false
	}
	resp, terr := g.provider.OpenChat(ctx, token, outBody)
	if terr != nil {
		return false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return false
	}
	if stream {
		_ = upstream.Stream(w, newModelRewriter(resp.Body, requestedModel))
		resp.Body.Close()
		return true
	}
	agg, aerr := upstream.Aggregate(newModelRewriter(resp.Body, requestedModel))
	resp.Body.Close()
	if aerr != nil {
		return false
	}
	if _, ok := agg["model"]; ok {
		agg["model"] = requestedModel
	}
	writeJSON(w, http.StatusOK, agg)
	return true
}

// candidates 返回未冷却的启用账号。
func (g *Gateway) candidates() []Account {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Account
	for _, a := range g.store.Enabled() {
		if until, ok := g.cooldowns[a.ID]; ok {
			if until.After(now) {
				continue
			}
			delete(g.cooldowns, a.ID)
		}
		out = append(out, a)
	}
	return out
}

func (g *Gateway) setCooldown(id string) {
	g.mu.Lock()
	g.cooldowns[id] = time.Now().Add(cooldownDuration)
	g.mu.Unlock()
}

// ensureToken 返回可用 accessToken：临期则先刷新（失败回退旧 token）。
func (g *Gateway) ensureToken(ctx context.Context, a Account) string {
	if a.AccessToken == "" {
		if a.CanRefresh() {
			return g.refreshAccount(ctx, a, true)
		}
		return ""
	}
	if a.IsExpiring() && a.CanRefresh() {
		if t := g.refreshAccount(ctx, a, false); t != "" {
			return t
		}
		return a.AccessToken
	}
	return a.AccessToken
}

// refreshWaiter 单飞刷新的共享结果：done 关闭后 token 字段可安全读取（happens-before）。
type refreshWaiter struct {
	done  chan struct{}
	token string
}

// refreshAccount 单飞刷新：同账号（不分 force）并发只发一次网络请求。
// 用「共享结果字段 + close(done) 广播」而非向 channel 逐个发值，确保任意数量的
// 等待者都能读到同一结果（close 对所有接收者可见，无缓冲区容量限制）。
// force 与非 force 合并到同一 key：避免两条路径拿同一 refreshToken 并发刷新导致
// 上游轮换后一方失效（code-reviewer 发现 #2）。
func (g *Gateway) refreshAccount(ctx context.Context, a Account, force bool) string {
	key := a.ID
	g.mu.Lock()
	if w, ok := g.flights[key]; ok {
		g.mu.Unlock()
		<-w.done
		return w.token
	}
	w := &refreshWaiter{done: make(chan struct{})}
	g.flights[key] = w
	g.mu.Unlock()

	w.token = g.doRefresh(ctx, a)

	g.mu.Lock()
	delete(g.flights, key)
	g.mu.Unlock()
	close(w.done) // 广播：所有等待者随后读 w.token 都得到同一结果
	return w.token
}

func (g *Gateway) doRefresh(ctx context.Context, a Account) string {
	cur, ok := g.store.Get(a.ID)
	if !ok || !cur.CanRefresh() {
		return ""
	}
	res, err := g.provider.Refresh(ctx, cur.RefreshToken)
	if err != nil {
		log.Printf("raccoon refresh uid=%s failed: %v", shortID(a.ID), err)
		return ""
	}
	expMs := jwtExpiryUnix(res.AccessToken) * 1000
	if expMs <= 0 {
		expMs = cur.ExpiresAt
	}
	g.store.UpdateTokensIfCurrent(a.ID, cur.AccessToken, res.AccessToken, res.RefreshToken, expMs)
	log.Printf("raccoon refresh uid=%s: token 已刷新", shortID(a.ID))
	return res.AccessToken
}

func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
