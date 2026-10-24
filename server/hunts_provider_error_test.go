package server

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/hunting"
	"github.com/Autumn-27/norma/llm"
)

func TestHuntProviderErrorClassificationDoesNotExposeProviderText(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"expired", `openai-responses: HTTP 401: {"code":"expired_secret_key"}`, "만료"},
		{"generic_auth", `HTTP status=401: {"code":"invalid_api_key"}`, "인증에 실패"},
		{"json_status", `{"status_code":401,"code":"expired_secret_key"}`, "만료"},
		{"unauthorized", `401 Unauthorized`, "인증에 실패"},
		{"rate_limit", `HTTP/2 429: rate_limit_exceeded`, "요청 한도"},
		{"no_credits", `openai-responses: You have no credits remaining. Add credits to continue using the API`, "크레딧"},
		{"insufficient_quota", `HTTP 402: {"code":"insufficient_quota"}`, "크레딧"},
		{"generic_failure", `unexpected response with a private request fragment`, "호출에 실패"},
		{"code_without_401", `HTTP 500: expired_secret_key`, "호출에 실패"},
		{"status_without_expired_code", `HTTP 401: not_expired_secret_key`, "인증에 실패"},
		{"number_is_not_status", `request_id=401 expired_secret_key`, "호출에 실패"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const private = "https://private-model.example.invalid/path?api_key=fixture-secret-123"
			original := errors.New(tc.body + " " + private)
			wrapped := wrapHuntProviderError(original)
			var classified *huntProviderCallError
			if !errors.As(wrapped, &classified) || !errors.Is(wrapped, original) {
				t.Fatal("provider error did not preserve its internal cause")
			}
			if !strings.Contains(wrapped.Error(), tc.want) {
				t.Fatalf("classification=%q, want %q", wrapped.Error(), tc.want)
			}
			if strings.Contains(wrapped.Error(), "fixture-secret") || strings.Contains(wrapped.Error(), "example.invalid") || strings.Contains(wrapped.Error(), "request fragment") || strings.Contains(wrapped.Error(), "expired_secret_key") {
				t.Fatal("provider response or endpoint escaped into the public message")
			}
			if tc.want != "만료" && strings.Contains(wrapped.Error(), "만료") {
				t.Fatal("key expiry was inferred without both status and explicit code")
			}
		})
	}
}

func TestHuntProviderErrorPreservesContextAndBudgetIdentity(t *testing.T) {
	if wrapHuntProviderError(nil) != nil {
		t.Fatal("success became an error")
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, agent.ErrInvestigationBudget, hunting.ErrBudget} {
		original := fmt.Errorf("bounded execution: %w", cause)
		wrapped := wrapHuntProviderError(original)
		var classified *huntProviderCallError
		if wrapped != original || !errors.Is(wrapped, cause) || errors.As(wrapped, &classified) {
			t.Fatalf("control-flow error became a model failure: %v", cause)
		}
	}
	original := wrapHuntProviderError(errors.New("HTTP 401"))
	if wrapHuntProviderError(original) != original {
		t.Fatal("provider error was wrapped twice")
	}
}

type huntFailingProvider struct {
	err   error
	calls int
}

func (p *huntFailingProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	return llm.Message{}, "", llm.Usage{InputTokens: 7}, p.err
}

func (p *huntFailingProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.calls++
		yield(llm.StreamEvent{}, p.err)
	}
}

func TestHuntProviderCompleteAndStreamClassifyOnlyActualProviderFailures(t *testing.T) {
	original := errors.New("HTTP 401 expired_secret_key fixture-secret-123")
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream_%t", stream), func(t *testing.T) {
			base := &huntFailingProvider{err: original}
			p := &huntProvider{base: base}
			var got error
			if stream {
				for _, err := range p.Stream(t.Context(), llm.CompletionRequest{}) {
					got = err
				}
			} else {
				_, _, _, got = p.Complete(t.Context(), llm.CompletionRequest{})
			}
			var classified *huntProviderCallError
			if !errors.As(got, &classified) || !errors.Is(got, original) || strings.Contains(got.Error(), "fixture-secret") || base.calls != 1 {
				t.Fatal("actual provider error was not safely classified exactly once")
			}
			calls, input, _ := p.snapshot()
			if calls != 1 || (!stream && input != 7) {
				t.Fatal("classification changed request or usage accounting")
			}
			p.limited = true
			if stream {
				for _, err := range p.Stream(t.Context(), llm.CompletionRequest{}) {
					got = err
				}
			} else {
				_, _, _, got = p.Complete(t.Context(), llm.CompletionRequest{})
			}
			if !errors.Is(got, agent.ErrInvestigationBudget) || errors.As(got, &classified) || base.calls != 1 {
				t.Fatal("budget rejection called the provider or became a model failure")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if stream {
				for _, err := range p.Stream(ctx, llm.CompletionRequest{}) {
					got = err
				}
			} else {
				_, _, _, got = p.Complete(ctx, llm.CompletionRequest{})
			}
			if !errors.Is(got, context.Canceled) || errors.As(got, &classified) || base.calls != 1 {
				t.Fatal("cancelled execution reached the provider or became a model failure")
			}
		})
	}
}

func TestHuntExecutionFailurePreservesTerminalPrecedence(t *testing.T) {
	providerErr := wrapHuntProviderError(errors.New("HTTP 401 expired_secret_key fixture-secret-123"))
	for _, tc := range []struct {
		name, initial, wantStatus, wantMessage     string
		runErr, persistErr, contextErr, serviceErr error
		exhausted                                  bool
	}{
		{name: "provider", initial: "failed", wantStatus: "model_error", wantMessage: "만료", runErr: fmt.Errorf("design: %w", providerErr)},
		{name: "persist", initial: "failed", wantStatus: "interrupted", wantMessage: "근거 저장", runErr: providerErr, persistErr: errors.New("private store error")},
		{name: "budget", initial: "failed", wantStatus: "budget_exhausted", wantMessage: "누적 모델", runErr: providerErr, exhausted: true},
		{name: "budget_over_persist", initial: "failed", wantStatus: "budget_exhausted", wantMessage: "누적 모델", runErr: providerErr, exhausted: true, persistErr: errors.New("private store error")},
		{name: "deadline", initial: "budget_exhausted", wantStatus: "budget_exhausted", wantMessage: "제한시간", runErr: providerErr, contextErr: context.DeadlineExceeded},
		{name: "cancel", initial: "cancelled", wantStatus: "cancelled", wantMessage: "헌팅을 완료", runErr: providerErr, contextErr: context.Canceled},
		{name: "shutdown", initial: "failed", wantStatus: "interrupted", wantMessage: "서비스 종료", runErr: providerErr, exhausted: true, contextErr: context.DeadlineExceeded, serviceErr: context.Canceled},
		{name: "ordinary_validation", initial: "failed", wantStatus: "failed", wantMessage: "헌팅을 완료", runErr: errors.New("invalid design")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := hunting.Result{Status: tc.initial, Error: "보존된 단계 안내"}
			message := huntExecutionFailure(&result, tc.runErr, tc.persistErr, tc.exhausted, tc.contextErr, tc.serviceErr)
			if result.Status != tc.wantStatus || !strings.Contains(message, tc.wantMessage) {
				t.Fatalf("status=%s message=%q", result.Status, message)
			}
			if strings.Contains(message, "fixture-secret") || strings.Contains(result.Error, "fixture-secret") {
				t.Fatal("private provider body escaped into a stored public message")
			}
			if tc.contextErr == nil && tc.runErr != nil && errors.Is(tc.runErr, providerErr) && result.Error != message {
				t.Fatal("run and result disagree about the final safe model failure")
			}
		})
	}
	result := hunting.Result{Status: "completed"}
	if message := huntExecutionFailure(&result, nil, nil, false, nil, nil); message != "" || result.Status != "completed" || result.Error != "" {
		t.Fatal("successful execution acquired an error")
	}
}
