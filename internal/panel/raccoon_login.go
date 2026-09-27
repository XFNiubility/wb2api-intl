// raccoon_login.go 面板内的小浣熊子网关登录编排。
//
// 两种登录方式：
//
//	POST /panel/api/raccoon/login/password  → body {phone,password,nation_code?} 直登落号（推荐）
//	GET  /panel/api/raccoon/accounts        → 列出小浣熊账号（脱敏）
//	POST /panel/api/raccoon/accounts/{id}/remove → 删除
//
// 密码直登会在网关侧 AES 加密敏感字段后调上游 login_with_password；
// 触发验证码时返回错误，提示用户到官方网页登录后用 token 方式（暂略）。
// Raccoon 未注入（子网关未启用）时全部返回 501。
package panel

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

func (p *Panel) raccoonLoginPassword(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Raccoon == nil {
		writeErr(w, http.StatusNotImplemented, "小浣熊子网关未启用（config.raccoon.enabled=false）")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req struct {
		Phone      string `json:"phone"`
		Password   string `json:"password"`
		NationCode string `json:"nation_code"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Phone == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "缺少 phone 或 password 字段")
		return
	}
	acc, err := p.cfg.Raccoon.LoginWithPassword(r.Context(), req.NationCode, req.Phone, req.Password)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	log.Printf("panel: 小浣熊密码登录落号 id=%s name=%q", acc.ID, acc.Name)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"id":       acc.ID,
		"name":     acc.Name,
		"org_name": acc.OrgName,
	})
}

func (p *Panel) raccoonLoginToken(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Raccoon == nil {
		writeErr(w, http.StatusNotImplemented, "小浣熊子网关未启用（config.raccoon.enabled=false）")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var req struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.AccessToken == "" {
		writeErr(w, http.StatusBadRequest, "缺少 access_token 字段")
		return
	}
	acc, err := p.cfg.Raccoon.LoginWithToken(req.AccessToken, req.RefreshToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Printf("panel: 小浣熊 token 登录落号 id=%s name=%q", acc.ID, acc.Name)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"id":       acc.ID,
		"name":     acc.Name,
		"org_name": acc.OrgName,
	})
}

func (p *Panel) raccoonAccounts(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Raccoon == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": false, "accounts": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"enabled":  true,
		"accounts": p.cfg.Raccoon.AccountsView(),
	})
}

func (p *Panel) raccoonAccountRemove(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Raccoon == nil {
		writeErr(w, http.StatusNotImplemented, "小浣熊子网关未启用")
		return
	}
	id := r.PathValue("id")
	if err := p.cfg.Raccoon.RemoveAccount(id); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (p *Panel) raccoonAccountCheckin(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Raccoon == nil {
		writeErr(w, http.StatusNotImplemented, "小浣熊子网关未启用")
		return
	}
	id := r.PathValue("id")
	ok, msg, err := p.cfg.Raccoon.CheckinOneView(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "message": msg})
}

func (p *Panel) raccoonAccountBalance(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Raccoon == nil {
		writeErr(w, http.StatusNotImplemented, "小浣熊子网关未启用")
		return
	}
	id := r.PathValue("id")
	bal, err := p.cfg.Raccoon.BalanceView(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "balance": bal})
}

func (p *Panel) raccoonCheckinAll(w http.ResponseWriter, r *http.Request) {
	if p.cfg.Raccoon == nil {
		writeErr(w, http.StatusNotImplemented, "小浣熊子网关未启用")
		return
	}
	reps := p.cfg.Raccoon.CheckinAllView(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reports": reps})
}
