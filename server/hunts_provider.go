package server

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"regexp"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/hunting"
	"github.com/Autumn-27/norma/llm"
)

// Only fixed messages cross the hunting API boundary. The original error stays
// available through Unwrap for cancellation/budget handling and private audit.
type huntProviderCallError struct {
	cause   error
	message string
}

func (e *huntProviderCallError) Error() string { return e.message }
func (e *huntProviderCallError) Unwrap() error { return e.cause }

var huntProviderHTTPStatus = regexp.MustCompile(`(?i)(?:\b(?:http(?:/\d(?:\.\d)?)?(?:\s+status)?|status(?:[_ -]*code)?|api\s+error)[\s"'=:]*(401|429)\b|\b(401)\s+unauthorized\b|\b(429)\s+too\s+many\s+requests\b)`)
var huntExpiredSecretCode = regexp.MustCompile(`\bexpired_secret_key\b`)
var huntNoCreditsCode = regexp.MustCompile(`\b(?:you have no credits remaining|insufficient_quota)\b`)

func wrapHuntProviderError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, agent.ErrInvestigationBudget) || errors.Is(err, hunting.ErrBudget) {
		return err
	}
	var existing *huntProviderCallError
	if errors.As(err, &existing) {
		return err
	}
	message := "LLM 호출에 실패했습니다. 모델 연결 상태와 설정을 확인해 주세요."
	// Provider bodies may contain credentials, URLs or request fragments. Read
	// only known status/code markers; never include their text in the message.
	value := strings.ToLower(err.Error())
	if huntNoCreditsCode.MatchString(value) {
		return &huntProviderCallError{cause: err, message: "LLM API 크레딧이 소진되었습니다. 계정의 사용량과 결제 상태를 확인해 주세요."}
	}
	matches := huntProviderHTTPStatus.FindStringSubmatch(value)
	if len(matches) == 0 {
		return &huntProviderCallError{cause: err, message: message}
	}
	for _, match := range matches[1:] {
		switch match {
		case "401":
			message = "LLM 인증에 실패했습니다 (HTTP 401). 모델 연결 설정의 API 키를 확인해 주세요."
			if huntExpiredSecretCode.MatchString(value) {
				message = "LLM API 키가 만료되었습니다 (HTTP 401). 모델 연결 설정에서 키를 갱신해 주세요."
			}
		case "429":
			message = "LLM 요청 한도에 도달했습니다 (HTTP 429). 모델의 사용 한도를 확인한 뒤 다시 실행해 주세요."
		}
	}
	return &huntProviderCallError{cause: err, message: message}
}

// This outer budget spans design and every stage. Reusing Investigator never
// resets the campaign's cost envelope. Reserve before sending, including failed
// calls and gateways that omit usage. No extra retries are introduced here.
const (
	huntProviderMaxCalls     = 24
	huntProviderReservedBytes = 1 << 20
)

type huntProvider struct {
	mu                             sync.Mutex
	base                           llm.Provider
	calls, reserved, input, output int64
	limited                        bool
}

func (p *huntProvider) reserve(req *llm.CompletionRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if req.MaxTokens <= 0 || req.MaxTokens > 6000 {
		req.MaxTokens = 6000
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	reserve := int64(len(raw) + req.MaxTokens + 256)
	if p.limited || len(raw) > 64000 || p.calls >= huntProviderMaxCalls || p.reserved+reserve > huntProviderReservedBytes {
		p.limited = true
		return agent.ErrInvestigationBudget
	}
	p.calls++
	p.reserved += reserve
	return nil
}
func (p *huntProvider) add(u llm.Usage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.input += int64(u.InputTokens + u.CacheReadTokens + u.CacheWriteTokens)
	p.output += int64(u.OutputTokens)
}
func (p *huntProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if err := ctx.Err(); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	if err := p.reserve(&req); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	m, reason, u, err := p.base.Complete(ctx, req)
	p.add(u)
	return m, reason, u, wrapHuntProviderError(err)
}
func (p *huntProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if err := p.reserve(&req); err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		acc := llm.NewAccumulator()
		defer func() { p.add(acc.Usage) }()
		for ev, err := range p.base.Stream(ctx, req) {
			if err == nil {
				acc.Add(ev)
			}
			if !yield(ev, wrapHuntProviderError(err)) {
				return
			}
		}
	}
}
func (p *huntProvider) snapshot() (int64, int64, int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, p.input, p.output
}
func (p *huntProvider) exhausted() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.limited }
