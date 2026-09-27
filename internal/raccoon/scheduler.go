// scheduler.go 小浣熊子网关的每日签到定时器 + 批量签到/积分入口。
//
// 与主 scheduler 独立（小浣熊账号池与 CodeBuddy 隔离）：Gateway 自带一个
// 每日整点触发的 goroutine，对池内所有启用账号跑一次签到（幂等）。
package raccoon

import (
	"context"
	"log"
	"sync"
	"time"
)

// CheckinReport 单账号签到结果（面板/日志用）。
type CheckinReport struct {
	AccountID string `json:"account_id"`
	Name      string `json:"name"`
	OK        bool   `json:"ok"`
	Message   string `json:"message"`
}

// CheckinAll 对池内所有启用账号执行一次签到（账号间串行，间隔 800ms 限速）。
// token 临期自动刷新；单账号失败只记录不中断。
func (g *Gateway) CheckinAll(ctx context.Context) []CheckinReport {
	accts := g.store.Enabled()
	reports := make([]CheckinReport, 0, len(accts))
	for i, a := range accts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return reports
			case <-time.After(800 * time.Millisecond):
			}
		}
		rep := CheckinReport{AccountID: a.ID, Name: a.Name}
		token := g.ensureToken(ctx, a)
		if token == "" {
			rep.Message = "无可用凭证"
			reports = append(reports, rep)
			log.Printf("raccoon checkin uid=%s: 无可用凭证", shortID(a.ID))
			continue
		}
		res, err := g.provider.DailyCheckin(ctx, token)
		if err != nil {
			rep.Message = err.Error()
			log.Printf("raccoon checkin uid=%s: %v", shortID(a.ID), err)
		} else {
			rep.OK = true
			rep.Message = res.Message
			log.Printf("raccoon checkin uid=%s: %s", shortID(a.ID), res.Message)
		}
		reports = append(reports, rep)
	}
	return reports
}

// CheckinOne 对单账号签到（面板「一键签到」用）。
func (g *Gateway) CheckinOne(ctx context.Context, id string) (CheckinReport, error) {
	a, ok := g.store.Get(id)
	if !ok {
		return CheckinReport{}, &UpstreamError{Status: 404, Msg: "账号不存在"}
	}
	rep := CheckinReport{AccountID: a.ID, Name: a.Name}
	token := g.ensureToken(ctx, a)
	if token == "" {
		rep.Message = "无可用凭证"
		return rep, nil
	}
	res, err := g.provider.DailyCheckin(ctx, token)
	if err != nil {
		rep.Message = err.Error()
		return rep, nil
	}
	rep.OK = true
	rep.Message = res.Message
	return rep, nil
}

// Balance 查询单账号积分余额（面板展示用）。
func (g *Gateway) Balance(ctx context.Context, id string) (*BalanceResult, error) {
	a, ok := g.store.Get(id)
	if !ok {
		return nil, &UpstreamError{Status: 404, Msg: "账号不存在"}
	}
	token := g.ensureToken(ctx, a)
	if token == "" {
		return nil, &UpstreamError{Status: 401, Msg: "无可用凭证"}
	}
	return g.provider.QueryBalance(ctx, token)
}

// StartDailyCheckin 启动每日签到定时器：每天在 hours 指定的整点各跑一次 CheckinAll。
// hours 为空回落 [9]。返回停止函数；重复调用前应先停旧的（Gateway 只应启一次）。
func (g *Gateway) StartDailyCheckin(hours []int) (stop func()) {
	if len(hours) == 0 {
		hours = []int{9}
	}
	// 去重 + 限定 0-23。
	seen := map[int]bool{}
	var valid []int
	for _, h := range hours {
		if h >= 0 && h <= 23 && !seen[h] {
			seen[h] = true
			valid = append(valid, h)
		}
	}
	if len(valid) == 0 {
		valid = []int{9}
	}

	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	go g.checkinLoop(ctx, valid)
	return func() { once.Do(cancel) }
}

// checkinLoop 每分钟检查一次是否命中签到整点；命中且当天未跑过则触发 CheckinAll。
func (g *Gateway) checkinLoop(ctx context.Context, hours []int) {
	log.Printf("raccoon: 每日签到定时器已启动，整点 %v", hours)
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastRun := "" // "YYYY-MM-DD-H"，防同一整点内重复触发
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			h := now.Hour()
			hit := false
			for _, hh := range hours {
				if hh == h {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			key := now.Format("2006-01-02") + "-" + itoa(h)
			if key == lastRun {
				continue
			}
			lastRun = key
			reps := g.CheckinAll(ctx)
			log.Printf("raccoon: 每日签到完成，共 %d 个账号", len(reps))
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [3]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
