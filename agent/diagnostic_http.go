package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
)

// diagnosticHTTPTool is the only network-capable tool in a diagnostic follow-up.
// The task Guard checks the saved URL scopes and a shared 20-request budget.
var diagnosticHTTPClient = func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}()

func diagnosticHTTPTool(g *guard.Guard) actool.CoreTool {
	return readTool("scoped_http_get", "저장된 진단 범위 안의 URL을 GET 또는 HEAD로만 조회합니다. 리다이렉트는 따르지 않고 작업 전체에서 최대 20회 요청할 수 있습니다. 결과는 관측 사실이며 취약점 확정이 아닙니다.", obj(map[string]any{
		"url":    str("저장된 진단 범위 내의 절대 HTTP(S) URL"),
		"method": map[string]any{"type": "string", "enum": []string{"GET", "HEAD"}, "description": "읽기 전용 HTTP 방법"},
	}, "url", "method"), func(ctx context.Context, input json.RawMessage) (actool.Result, error) {
		if len(input) > 5000 {
			return actool.Errorf("요청 입력이 너무 깁니다"), nil
		}
		var in struct {
			URL    string `json:"url"`
			Method string `json:"method"`
		}
		if err := json.Unmarshal(input, &in); err != nil || in.URL == "" {
			return actool.Errorf("URL과 GET/HEAD 방법이 필요합니다"), nil
		}
		if err := g.UseDiagnosticRequest(in.Method, in.URL); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		defer g.FinishDiagnosticRequest()
		req, err := http.NewRequestWithContext(ctx, in.Method, in.URL, nil)
		if err != nil {
			return actool.Errorf("요청을 만들 수 없습니다"), nil
		}
		resp, err := diagnosticHTTPClient.Do(req)
		if err != nil {
			return actool.Errorf("읽기 요청 실패: " + err.Error()), nil
		}
		defer resp.Body.Close()
		body := ""
		truncated := false
		if in.Method == "GET" {
			limited := io.LimitReader(resp.Body, 8193)
			b, readErr := io.ReadAll(limited)
			if readErr != nil {
				return actool.Errorf("응답 본문을 읽지 못했습니다"), nil
			}
			if len(b) > 8192 {
				b = b[:8192]
				truncated = true
			}
			body = strings.ToValidUTF8(string(b), "�")
		}
		return jsonResult(map[string]any{
			"url": in.URL, "method": in.Method, "status_code": resp.StatusCode,
			"content_type": resp.Header.Get("Content-Type"), "body": body,
			"body_truncated": truncated, "redirect_followed": false,
		})
	})
}
