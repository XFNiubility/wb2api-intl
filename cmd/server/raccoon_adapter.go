package main

import (
	"context"

	"github.com/linguo2625469/workbuddy2api-panel/internal/panel"
	"github.com/linguo2625469/workbuddy2api-panel/internal/raccoon"
)

// raccoonPanelAdapter 把 raccoon.Gateway 适配为 panel.RaccoonLogin 接口，
// 隔离 panel 与 raccoon 的类型依赖（两包互不 import，由 main 桥接）。
type raccoonPanelAdapter struct {
	gw *raccoon.Gateway
}

func (a raccoonPanelAdapter) LoginWithPassword(ctx context.Context, nationCode, phone, password string) (panel.RaccoonAccountView, error) {
	acc, err := a.gw.LoginWithPassword(ctx, nationCode, phone, password)
	if err != nil {
		return panel.RaccoonAccountView{}, err
	}
	return toView(acc), nil
}

func (a raccoonPanelAdapter) LoginWithToken(accessToken, refreshToken string) (panel.RaccoonAccountView, error) {
	acc, err := a.gw.LoginWithToken(accessToken, refreshToken)
	if err != nil {
		return panel.RaccoonAccountView{}, err
	}
	return toView(acc), nil
}

func (a raccoonPanelAdapter) AccountsView() []panel.RaccoonAccountView {
	src := a.gw.Accounts()
	out := make([]panel.RaccoonAccountView, 0, len(src))
	for _, acc := range src {
		out = append(out, toView(acc))
	}
	return out
}

func (a raccoonPanelAdapter) RemoveAccount(id string) error { return a.gw.RemoveAccount(id) }

func (a raccoonPanelAdapter) CheckinOneView(ctx context.Context, id string) (bool, string, error) {
	rep, err := a.gw.CheckinOne(ctx, id)
	if err != nil {
		return false, "", err
	}
	return rep.OK, rep.Message, nil
}

func (a raccoonPanelAdapter) CheckinAllView(ctx context.Context) []panel.RaccoonCheckinView {
	reps := a.gw.CheckinAll(ctx)
	out := make([]panel.RaccoonCheckinView, 0, len(reps))
	for _, r := range reps {
		out = append(out, panel.RaccoonCheckinView{AccountID: r.AccountID, Name: r.Name, OK: r.OK, Message: r.Message})
	}
	return out
}

func (a raccoonPanelAdapter) BalanceView(ctx context.Context, id string) (map[string]int64, error) {
	b, err := a.gw.Balance(ctx, id)
	if err != nil {
		return nil, err
	}
	return map[string]int64{
		"available": b.Available, "daily": b.Daily, "monthly": b.Monthly,
		"reward": b.Reward, "topup": b.Topup,
	}, nil
}

// toView 把 raccoon.Account（Accounts() 已脱敏：AccessToken 仅末 4 位）映射为面板视图。
func toView(acc raccoon.Account) panel.RaccoonAccountView {
	return panel.RaccoonAccountView{
		ID:       acc.ID,
		Name:     acc.Name,
		UserID:   acc.UserID,
		OrgName:  acc.OrgName,
		Enabled:  acc.Enabled,
		TokenTip: acc.AccessToken, // 已是脱敏末 4 位
	}
}
