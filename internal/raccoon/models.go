package raccoon

import (
	"fmt"
	"math"
	"strings"
)

// ModelInfo 归一化后的模型信息（对齐 APK RaccoonModels.ModelInfo）。
type ModelInfo struct {
	ID                string
	Name              string
	Description       string
	Tags              []string
	ContextWindow     int64
	MaxTokens         int64
	SupportsImages    bool
	SupportsReasoning bool
	Credits           string
	Visible           bool
}

// DefaultModelID 上游默认模型（default-llm-config.json 预置）。
const DefaultModelID = "raccoon-chat-ml-5-5"

// FallbackModels 目录拉取失败时的内置兜底清单（对齐 APK fallbackModels）。
func FallbackModels() []ModelInfo {
	return []ModelInfo{
		{ID: "raccoon-8c4485", Name: "Raccoon-Work",
			Description:   "适合复杂办公任务、代码开发、调试和图像识别等任务（目录默认旗舰，自称 GPT-5）",
			Tags:          []string{"general", "office", "code", "vision"},
			ContextWindow: 1000000, MaxTokens: 100000, SupportsImages: true, Credits: "x1 credits", Visible: true},
		{ID: "raccoon-19b265", Name: "Raccoon-Work-260817-A",
			Description:   "适合复杂办公任务、代码开发和综合分析等任务（A/B 变体 A，自称 GPT-5）",
			Tags:          []string{"general", "office", "code", "analysis"},
			ContextWindow: 1000000, MaxTokens: 100000, Credits: "x1 credits", Visible: true},
		{ID: "raccoon-405a1c", Name: "Raccoon-Work-260817-B",
			Description:   "适合通用对话、轻量代码和内容处理等任务（A/B 变体 B，自称 GPT-5）",
			Tags:          []string{"general", "chat", "rewrite", "summary", "fast"},
			ContextWindow: 1000000, MaxTokens: 100000, Credits: "x1 credits", Visible: true},
		{ID: DefaultModelID, Name: "Raccoon Chat (默认)",
			Description:   "小浣熊默认对话模型（default-llm-config.json 预置）。",
			Tags:          []string{},
			ContextWindow: 180000, MaxTokens: 80000, SupportsReasoning: true, Visible: true},
		{ID: "sn-sensenova-6-8-flash-lite", Name: "SenseNova 6.8 Flash Lite",
			Description:   "轻量模型，用于标题生成等小任务。",
			Tags:          []string{},
			ContextWindow: 256000, MaxTokens: 63999, SupportsReasoning: true, Credits: "x0.5 credits", Visible: true},
	}
}

// ToOpenAI 输出 OpenAI /v1/models data 项。ownedBy 固定为 "raccoon"。
func (m ModelInfo) ToOpenAI(ownedBy string) map[string]any {
	out := map[string]any{
		"id":                m.ID,
		"object":            "model",
		"created":           0,
		"owned_by":          ownedBy,
		"name":              m.Name,
		"description":       m.Description,
		"tags":              strings.Join(m.Tags, ","),
		"supportsImages":    m.SupportsImages,
		"supportsReasoning": m.SupportsReasoning,
		"credits":           m.Credits,
	}
	if m.ContextWindow > 0 {
		out["maxInputTokens"] = m.ContextWindow
	}
	if m.MaxTokens > 0 {
		out["maxOutputTokens"] = m.MaxTokens
	}
	return out
}

// parseCatalog 解析上游 model_catalog 响应（categories[].models[]）。
// 字段名对齐 APK RaccoonModels.normalizeEntry：id/model_name、name/display_name、
// description/display_description、tags、context_window/contextWindow、
// max_tokens/maxTokens、billing_multiplier/billing_effective_multiplier、vision/image tags。
func parseCatalog(payload map[string]any) []ModelInfo {
	data := payload
	if d, ok := payload["data"].(map[string]any); ok {
		data = d
	}
	categories, _ := data["categories"].([]any)
	if categories == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []ModelInfo
	for _, c := range categories {
		cat, ok := c.(map[string]any)
		if !ok {
			continue
		}
		entries, _ := cat["models"].([]any)
		for _, e := range entries {
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			m := normalizeEntry(entry)
			if m == nil || m.ID == "" || seen[m.ID] {
				continue
			}
			seen[m.ID] = true
			out = append(out, *m)
		}
	}
	return out
}

func normalizeEntry(entry map[string]any) *ModelInfo {
	id := firstNonEmpty(textOf(entry, "id"), textOf(entry, "model_name"))
	if id == "" {
		return nil
	}
	params := objOf(entry, "params")
	name := firstNonEmpty(textOf(entry, "name"), textOf(entry, "display_name"), id)
	desc := firstNonEmpty(textOf(entry, "description"), textOf(entry, "display_description"))

	var tags []string
	if arr, ok := entry["tags"].([]any); ok {
		for _, t := range arr {
			if s, ok := t.(string); ok && s != "" {
				tags = append(tags, s)
			}
		}
	}

	ctx := pickInt(entry, params, "context_window", "contextWindow")
	maxTok := pickInt(entry, params, "max_tokens", "maxTokens")

	supportsImages := false
	for _, t := range tags {
		lt := strings.ToLower(t)
		if lt == "vision" || lt == "image" || lt == "image-understanding" {
			supportsImages = true
			break
		}
	}

	credits := ""
	if mult, ok := numberOf(firstNonNil(entry["billing_multiplier"], entry["billing_effective_multiplier"])); ok {
		credits = "x" + formatMultiplier(mult) + " credits"
	}

	return &ModelInfo{
		ID:             id,
		Name:           name,
		Description:    desc,
		Tags:           tags,
		ContextWindow:  ctx,
		MaxTokens:      maxTok,
		SupportsImages: supportsImages,
		Credits:        credits,
		Visible:        true,
	}
}

func pickInt(entry, params map[string]any, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := entry[k]; ok {
			if f, ok := num64(v); ok && !math.IsInf(f, 0) && !math.IsNaN(f) {
				return int64(f)
			}
		}
		if params != nil {
			if v, ok := params[k]; ok {
				if f, ok := num64(v); ok && !math.IsInf(f, 0) && !math.IsNaN(f) {
					return int64(f)
				}
			}
		}
	}
	return 0
}

func numberOf(v any) (float64, bool) {
	if v == nil {
		return 0, false
	}
	f, ok := num64(v)
	if !ok || math.IsInf(f, 0) || math.IsNaN(f) || f < 0 {
		return 0, false
	}
	return f, true
}

func firstNonNil(vals ...any) any {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

func formatMultiplier(v float64) string {
	rounded := math.Round(v*100) / 100
	if rounded == math.Floor(rounded) {
		return fmt.Sprintf("%d", int64(rounded))
	}
	s := fmt.Sprintf("%.2f", rounded)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	return s
}
