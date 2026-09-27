// raccoonlogin — 「办公小浣熊」账号登录辅助 CLI（移植自 APK AddAccountActivity）。
//
// 三个子命令：
//
//	raccoonlogin url                      → 生成 state，打印浏览器授权链接
//	raccoonlogin exchange <callback-url>  → 解析回调 code+state → 换取凭证 → 落盘账号
//	raccoonlogin manual <access> <refresh> → 手动粘贴 access/refresh token 落盘账号
//
// 账号写入 -store 指定的文件（默认 ./auths/raccoon-accounts.json），
// 与网关 config.raccoon.account_file 保持一致即可被子网关加载。
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/raccoon"
)

func main() {
	storePath := flag.String("store", "./auths/raccoon-accounts.json", "账号存储文件")
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		fatal("usage: raccoonlogin [-store FILE] <url|exchange <callback-url>|manual <access> <refresh>>")
	}

	prov := raccoon.NewProvider()
	ctx := context.Background()

	switch args[0] {
	case "url":
		state := randState()
		if err := os.WriteFile(statePath(), []byte(state), 0o600); err != nil {
			fatal("写 state 失败: %v", err)
		}
		fmt.Println("请在浏览器打开以下链接完成登录：")
		fmt.Println(prov.BuildAuthorizeURL(state))
		fmt.Println("\n登录后浏览器会跳转到 office-raccoon://auth/callback?code=...&state=... —— 复制整段回调 URL，然后执行：")
		fmt.Printf("  raccoonlogin -store %q exchange \"<回调URL>\"\n", *storePath)

	case "exchange":
		if len(args) < 2 {
			fatal("usage: raccoonlogin exchange <callback-url>")
		}
		code, state, ok := raccoon.ParseCallbackCode(args[1])
		if !ok {
			fatal("回调 URL 非法：无法解析 code/state")
		}
		if want, err := os.ReadFile(statePath()); err == nil && string(want) != state {
			fmt.Fprintf(os.Stderr, "警告：回调 state 与本地不一致（可能非本次登录），仍继续换取。\n")
		}
		ex, err := prov.ExchangeCode(ctx, code)
		if err != nil {
			fatal("换取凭证失败: %v", err)
		}
		saveAccount(*storePath, ex.AccessToken, ex.RefreshToken, ex.DisplayName, ex.OrgName, ex.OrgRole)
		os.Remove(statePath())

	case "manual":
		if len(args) < 3 {
			fatal("usage: raccoonlogin manual <access-token> <refresh-token>")
		}
		saveAccount(*storePath, args[1], args[2], "", "", "")

	default:
		fatal("unknown subcommand %q", args[0])
	}
}

func saveAccount(storePath, access, refresh, name, org, role string) {
	s := raccoon.NewStore(storePath)
	id := randState()
	if name == "" {
		name = "raccoon-" + id[:6]
	}
	acc := raccoon.Account{
		ID:           id,
		Name:         name,
		AccessToken:  access,
		RefreshToken: refresh,
		OrgName:      org,
		OfficeRole:   role,
		Enabled:      true,
		CreatedAt:    time.Now().UnixMilli(),
	}
	if err := s.Add(acc); err != nil {
		fatal("落盘账号失败: %v", err)
	}
	fmt.Printf("账号已保存到 %s（id=%s name=%s）\n", storePath, id, name)
}

func statePath() string {
	return os.TempDir() + string(os.PathSeparator) + "raccoon-login-state"
}

func randState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "raccoonlogin: "+format+"\n", args...)
	os.Exit(1)
}
