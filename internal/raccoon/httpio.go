package raccoon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// writeJSON 写 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError 写 OpenAI 风格错误。
func writeError(w http.ResponseWriter, status int, msg, typ string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{"message": msg, "type": typ},
	})
}

// readLimited 读请求体，最多 limit 字节。
func readLimited(r *http.Request, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, limit))
}

// readAllLimited 从 reader 读至多 limit 字节。
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit))
}

// modelRewriter 在把上游 SSE 交给 upstream.Aggregate/Stream 之前，
// 把每帧 JSON 里的 "model" 字段改写为客户端请求的 model（对齐 APK SseCompat.rewriteModel）。
// 它按 SSE 行边界工作：只重写 "data: {json}" 行的 model 字段，其余行原样透出。
type modelRewriter struct {
	br    *bufio.Reader
	model string
	buf   bytes.Buffer
	eof   bool
}

func newModelRewriter(r io.Reader, model string) *modelRewriter {
	return &modelRewriter{br: bufio.NewReaderSize(r, 64*1024), model: model}
}

func (m *modelRewriter) Read(p []byte) (int, error) {
	for m.buf.Len() == 0 && !m.eof {
		line, err := m.br.ReadBytes('\n')
		if len(line) > 0 {
			m.buf.Write(m.rewriteLine(line))
		}
		if err != nil {
			m.eof = true
			break
		}
	}
	if m.buf.Len() == 0 && m.eof {
		return 0, io.EOF
	}
	return m.buf.Read(p)
}

// rewriteLine 只对 "data: {...json...}" 行改写 model；[DONE] 与非 data 行原样返回。
func (m *modelRewriter) rewriteLine(line []byte) []byte {
	trimmed := bytes.TrimRight(line, "\r\n")
	const prefix = "data:"
	if !bytes.HasPrefix(trimmed, []byte(prefix)) {
		return line
	}
	payload := bytes.TrimSpace(trimmed[len(prefix):])
	if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
		return line
	}
	var obj map[string]any
	if json.Unmarshal(payload, &obj) != nil {
		return line
	}
	if _, ok := obj["model"]; ok {
		obj["model"] = m.model
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return line
	}
	tail := ""
	if bytes.HasSuffix(line, []byte("\r\n")) {
		tail = "\r\n"
	} else if bytes.HasSuffix(line, []byte("\n")) {
		tail = "\n"
	}
	return append([]byte("data: "), append(raw, []byte(tail)...)...)
}
