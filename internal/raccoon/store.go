package raccoon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Account 小浣熊账号凭证 + 池状态（对齐 APK RaccoonAccount，去掉 UI 专属字段）。
type Account struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt,omitempty"` // Unix 毫秒（对齐 APK JWT expiryMs）
	UserID       string `json:"userId"`
	Enabled      bool   `json:"enabled"`
	OrgName      string `json:"orgName,omitempty"`
	OfficeRole   string `json:"officeRole,omitempty"`
	CreatedAt    int64  `json:"createdAt"`
}

// CanRefresh 是否具备刷新条件。
func (a *Account) CanRefresh() bool { return strings.TrimSpace(a.RefreshToken) != "" }

// IsExpiring token 是否将在 5 分钟内过期（对齐 APK isExpiring）。
func (a *Account) IsExpiring() bool {
	if a.ExpiresAt <= 0 {
		return false
	}
	return time.Now().UnixMilli() >= a.ExpiresAt-300000
}

// TokenTail 末 4 位（脱敏展示）。
func (a *Account) TokenTail() string {
	if len(a.AccessToken) <= 4 {
		return a.AccessToken
	}
	return a.AccessToken[len(a.AccessToken)-4:]
}

// Store 账号存储：单 JSON 文件持久化 + 读写锁（对齐 APK AccountStore 语义）。
// 文件默认 <auth_dir>/raccoon-accounts.json，与 CodeBuddy 的 workbuddy-*.json 完全隔离。
type Store struct {
	mu       sync.RWMutex
	file     string
	accounts []*Account
}

// NewStore 打开（或初始化）存储文件。
func NewStore(file string) *Store {
	s := &Store{file: file}
	s.load()
	return s
}

func (s *Store) load() {
	raw, err := os.ReadFile(s.file)
	if err != nil {
		return
	}
	var doc struct {
		Accounts []*Account `json:"accounts"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return
	}
	for _, a := range doc.Accounts {
		if a != nil && a.ID != "" {
			s.accounts = append(s.accounts, a)
		}
	}
}

// persist 原子落盘（tmp + rename）。调用方需持写锁。
func (s *Store) persistLocked() error {
	if s.file == "" {
		return nil
	}
	if dir := filepath.Dir(s.file); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	doc := struct {
		Accounts []*Account `json:"accounts"`
	}{Accounts: s.accounts}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.file + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.file)
}

// List 返回账号快照副本。
func (s *Store) List() []Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, *a)
	}
	return out
}

// Get 按 id 取账号快照。
func (s *Store) Get(id string) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts {
		if a.ID == id {
			return *a, true
		}
	}
	return Account{}, false
}

// Add 新增或按 id 覆盖账号并落盘。
func (s *Store) Add(a Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.ID == "" {
		return fmt.Errorf("account id empty")
	}
	if a.CreatedAt == 0 {
		a.CreatedAt = time.Now().UnixMilli()
	}
	cp := a
	for i, ex := range s.accounts {
		if ex.ID == a.ID {
			s.accounts[i] = &cp
			return s.persistLocked()
		}
	}
	s.accounts = append(s.accounts, &cp)
	return s.persistLocked()
}

// Remove 删除账号并落盘。
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.accounts[:0]
	for _, a := range s.accounts {
		if a.ID != id {
			out = append(out, a)
		}
	}
	s.accounts = out
	return s.persistLocked()
}

// SetEnabled 启停账号并落盘。
func (s *Store) SetEnabled(id string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.ID == id {
			a.Enabled = enabled
			return s.persistLocked()
		}
	}
	return fmt.Errorf("account %s not found", id)
}

// UpdateTokensIfCurrent 条件更新 token：仅当当前 accessToken 仍等于 prevAccess 才写入，
// 防止并发刷新的 ABA 陈旧覆盖（对齐 APK updateTokensIfCurrent）。返回是否写入。
func (s *Store) UpdateTokensIfCurrent(id, prevAccess, access, refresh string, expiresAt int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.ID != id {
			continue
		}
		if a.AccessToken != prevAccess {
			return false // 已被其他 goroutine 刷新
		}
		a.AccessToken = access
		if refresh != "" {
			a.RefreshToken = refresh
		}
		if expiresAt > 0 {
			a.ExpiresAt = expiresAt
		}
		if uid := jwtUserID(access); uid != "" {
			a.UserID = uid
		}
		_ = s.persistLocked()
		return true
	}
	return false
}

// Enabled 返回启用账号快照，按 createdAt 升序（稳定轮换顺序）。
func (s *Store) Enabled() []Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Account
	for _, a := range s.accounts {
		if a.Enabled {
			out = append(out, *a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}
