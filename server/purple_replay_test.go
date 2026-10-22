package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPurpleReplayRoutesRemoved(t *testing.T) {
	s := &Server{jwtKey: []byte("purple-replay-test-key")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/exploration/findings/1/defense/replays"},
		{http.MethodGet, "/api/exploration/findings/1/defense/replays"},
		{http.MethodGet, "/api/exploration/findings/1/defense/replays/1/export"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			request := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("removed replay route returned %d: %s", response.Code, response.Body.String())
			}
		})
	}
}
