// checkin.go 小浣熊每日签到（桌面登录积分）与积分余额查询。
//
// 逆向自 APK RaccoonProvider.checkin / queryBalance：
//   - 签到：POST /api/web/desktop/v1/login/points/grant（桌面登录奖励，按天幂等）
//     头：Authorization Bearer / X-Client-Platform: desktop-windows /
//     X-Client-Version: v1.0.0 / X-Raccoon-Language: zh
//   - 余额：GET /api/web/points/v1/balance（available_points 等）
//
// 端点挂在 MainOrigin（xiaohuanxiong.com）下，非 LLM/Auth base。
package raccoon

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// timeNowDate 返回本地 YYYY-MM-DD（对账当日账单用）。
func timeNowDate() string { return time.Now().Format("2006-01-02") }

// checkin/balance 专用头（对齐桌面端指纹）。
func (p *Provider) desktopHeaders(token string) map[string]string {
	return map[string]string{
		"Accept":             "application/json",
		"Authorization":      "Bearer " + stripBearer(token),
		"X-Client-Platform":  "desktop-windows",
		"X-Client-Version":   "v1.0.0",
		"X-Raccoon-Language": "zh",
	}
}

// CheckinResult 签到结果。
type CheckinResult struct {
	Granted bool   // 本次是否发放了积分
	Points  int64  // 今日发放的积分数（未发放为 0）
	Message string // 可读文案（已发放 / 已领取 / 失败原因）
}

// DailyCheckin 触发桌面登录积分发放（每天一次，幂等）。
// 上游 200 即视为已处理：granted=true 表示本次发放，否则为今日已领取。
func (p *Provider) DailyCheckin(ctx context.Context, token string) (*CheckinResult, error) {
	url := p.MainOrigin + "/api/web/desktop/v1/login/points/grant"
	resp, err := p.requestJSON(ctx, http.MethodPost, url, []byte("{}"), p.desktopHeaders(token))
	if err != nil {
		return nil, &UpstreamError{Status: 502, Msg: "连接小浣熊签到接口失败: " + err.Error()}
	}
	if resp.status == 401 {
		return nil, &UpstreamError{Status: 401, Msg: "登录态已过期，无法签到"}
	}
	if resp.status < 200 || resp.status >= 300 {
		msg := firstNonEmpty(textOf(resp.payload, "message"), textOf(resp.payload, "msg"),
			fmt.Sprintf("签到返回 HTTP %d", resp.status))
		return nil, &UpstreamError{Status: resp.status, Msg: "小浣熊签到失败: " + msg}
	}
	data := objOf(resp.payload, "data")
	if data == nil {
		data = resp.payload
	}
	granted := false
	if b, ok := data["granted"].(bool); ok {
		granted = b
	}
	msg := "今日积分已领取"
	points := int64(0)
	if granted {
		msg = "桌面登录奖励已发放"
		// 发放数不在 grant 响应里，查当日账单对账取精确分数（对齐 APK bills 逻辑）。
		if pts := p.todayGrantPoints(ctx, token); pts > 0 {
			points = pts
			msg = fmt.Sprintf("桌面登录奖励已发放，今日积分 +%d", pts)
		}
	}
	return &CheckinResult{Granted: granted, Points: points, Message: msg}, nil
}

// todayGrantPoints 查当日积分账单，返回最近一笔发放（reward/daily_grant）的分数。
// 仅用于给签到成功补充精确分数，失败静默返回 0（不影响签到结果）。
func (p *Provider) todayGrantPoints(ctx context.Context, token string) int64 {
	url := p.MainOrigin + "/api/web/points/v1/bills?paging.limit=20&paging.offset=0"
	resp, err := p.requestJSON(ctx, http.MethodGet, url, nil, p.desktopHeaders(token))
	if err != nil || resp.status < 200 || resp.status >= 300 {
		return 0
	}
	data := objOf(resp.payload, "data")
	if data == nil {
		data = resp.payload
	}
	items, _ := data["items"].([]any)
	today := timeNowDate()
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		created := textOf(m, "created_at")
		if len(created) < 10 || created[:10] != today {
			continue
		}
		biz := textOf(m, "biz_type")
		if biz == "reward_grant" || biz == "daily_grant" {
			if pts, ok := optInt64(m, "points"); ok && pts > 0 {
				return pts
			}
		}
	}
	return 0
}

// BalanceResult 积分余额。
type BalanceResult struct {
	Available int64 // 可用积分
	Daily     int64 // 每日积分
	Monthly   int64 // 每月会员积分
	Reward    int64 // 奖励积分
	Topup     int64 // 充值积分
}

// QueryBalance 查询积分余额。
func (p *Provider) QueryBalance(ctx context.Context, token string) (*BalanceResult, error) {
	url := p.MainOrigin + "/api/web/points/v1/balance"
	resp, err := p.requestJSON(ctx, http.MethodGet, url, nil, p.desktopHeaders(token))
	if err != nil {
		return nil, &UpstreamError{Status: 502, Msg: "连接小浣熊积分接口失败: " + err.Error()}
	}
	if resp.status == 401 {
		return nil, &UpstreamError{Status: 401, Msg: "登录态已过期，无法查询积分"}
	}
	if resp.status < 200 || resp.status >= 300 {
		return nil, &UpstreamError{Status: resp.status, Msg: fmt.Sprintf("积分查询返回 HTTP %d", resp.status)}
	}
	data := objOf(resp.payload, "data")
	if data == nil {
		data = resp.payload
	}
	avail, _ := optInt64(data, "available_points")
	daily, _ := optInt64(data, "daily_points")
	monthly, _ := optInt64(data, "monthly_points")
	reward, _ := optInt64(data, "reward_points")
	topup, _ := optInt64(data, "topup_points")
	return &BalanceResult{
		Available: avail, Daily: daily, Monthly: monthly, Reward: reward, Topup: topup,
	}, nil
}
