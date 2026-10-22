package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
)

func TestPurpleSecuritySourceEncryptionAndTamper(t *testing.T) {
	s := &Server{jwtKey: []byte("source-test-key")}
	auth := securitysource.Credentials{Username: "reader", Password: "never-expose-this"}
	c, e := s.encryptSourceCredentials(auth)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(c), auth.Password) {
		t.Fatal("credential stored as plaintext")
	}
	out, e := s.securitySourceCredentials(&db.SecuritySource{SecretCipher: c})
	if e != nil || out != auth {
		t.Fatalf("roundtrip: %v", e)
	}
	c[len(c)-1] ^= 1
	if _, e := s.securitySourceCredentials(&db.SecuritySource{SecretCipher: c}); e == nil {
		t.Fatal("tampered credentials accepted")
	}
}
func TestPurpleSecuritySourceAPISecretRedactionAndRevisions(t *testing.T) {
	s, _, request := purpleAPIFixture(t)
	cfg := securitysource.Config{BaseURL: "https://siem.example.test:8089", Index: "security", AuditSourcetype: "audit", AlertSourcetype: "alert", CorrelationField: "artex_verification_id", ActionField: "action"}
	in := map[string]any{"name": "test-read-only", "config": cfg, "enabled": true, "expected_revision": 0, "username": "reader", "password": "source-secret-not-in-output"}
	post := func(method, path string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(in)
		return request(method, path, string(b))
	}
	w := post("POST", "/api/purple/sources")
	if w.Code != 201 || strings.Contains(w.Body.String(), "source-secret") || strings.Contains(w.Body.String(), "secret_cipher") {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	var source db.SecuritySource
	if e := json.Unmarshal(w.Body.Bytes(), &source); e != nil {
		t.Fatal(e)
	}
	if len(source.Config.Streams) != 2 || source.Config.Streams[0].Kind != "audit" || source.Config.Streams[1].Kind != "alert" {
		t.Fatalf("legacy config was not resolved into audit and alert streams: %+v", source.Config.Streams)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
	stored, e := s.m.pg.GetSecuritySource(t.Context(), source.ID)
	if e != nil {
		t.Fatal(e)
	}
	if len(stored.SecretCipher) == 0 || !source.CredentialSet {
		t.Fatal("encrypted credentials not stored")
	}
	if w = request("GET", "/api/purple/sources", ""); w.Code != 200 || strings.Contains(w.Body.String(), "source-secret") {
		t.Fatal("list disclosed credentials")
	}
	// Simulate a saved source from before the streams field existed. Opening
	// it in the new editor and saving unchanged must preserve the revision.
	legacyRaw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.m.pg.Exec(`UPDATE security_sources SET config=$2 WHERE id=$1`, source.ID, legacyRaw); e != nil {
		t.Fatal(e)
	}
	delete(in, "username")
	delete(in, "password")
	migrated := cfg
	migrated.Streams = securitysource.EffectiveStreams(cfg)
	migrated.Index, migrated.AuditSourcetype, migrated.AlertSourcetype = "", "", ""
	in["config"] = migrated
	in["expected_revision"] = source.Revision
	path := fmt.Sprintf("/api/purple/sources/%d", source.ID)
	w = post("PUT", path)
	if w.Code != 200 {
		t.Fatalf("legacy no-op save: %d %s", w.Code, w.Body)
	}
	var noChange db.SecuritySource
	if e = json.Unmarshal(w.Body.Bytes(), &noChange); e != nil || noChange.Revision != source.Revision {
		t.Fatalf("legacy no-op revision: %+v %v", noChange, e)
	}
	in["name"] = "renamed"
	w = post("PUT", path)
	if w.Code != 200 {
		t.Fatalf("preserve secret: %d %s", w.Code, w.Body)
	}
	after, _ := s.m.pg.GetSecuritySource(t.Context(), source.ID)
	if string(after.SecretCipher) != string(stored.SecretCipher) || after.Revision != 2 {
		t.Fatal("update lost credentials or revision")
	}
	if w = post("PUT", path); w.Code != 409 {
		t.Fatal("stale source edit accepted")
	}
	in["expected_revision"] = 2
	cfg.BaseURL = "https://other.example.test"
	in["config"] = cfg
	if w = post("PUT", path); w.Code != 400 {
		t.Fatal("credential silently forwarded to new endpoint")
	}
	if w = request("DELETE", path, `{}`); w.Code != 400 {
		t.Fatal("source deleted without revision", w.Code)
	}
	if w = request("DELETE", path, `{"expected_revision":1}`); w.Code != 409 {
		t.Fatal("source deleted using stale revision", w.Code)
	}
	w = request("DELETE", path, `{"expected_revision":2}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), fmt.Sprintf(`"deleted":"%d"`, source.ID)) {
		t.Fatal("delete source", w.Code, w.Body.String())
	}
	if _, e := s.m.pg.GetSecuritySource(t.Context(), source.ID); e != db.ErrSecuritySourceNotFound {
		t.Fatal("source credentials remained", e)
	}
	if w = request("DELETE", path, `{"expected_revision":2}`); w.Code != 404 {
		t.Fatal("repeated source deletion", w.Code)
	}
}

func TestPurpleSecuritySourceMultistreamSettingsAndProbeBounds(t *testing.T) {
	s, _, request := purpleAPIFixture(t)
	cfg := securitysource.Config{
		BaseURL: "https://siem.example.test:8089", CorrelationField: "artex_verification_id", ActionField: "action",
		Streams: []securitysource.LogStream{
			{Index: "ag_juice_shop", Sourcetype: "web_access", Kind: "audit", Label: "Juice Shop access", Asset: "juice-shop"},
			{Index: "ag_vuln_bank", Sourcetype: "web_access", Kind: "audit", Label: "Vuln Bank access", Asset: "vuln-bank"},
			{Index: "ag_alerts", Sourcetype: "notable", Kind: "alert", Label: "Detection alerts"},
		},
	}
	body, err := json.Marshal(map[string]any{"name": "multi-index", "config": cfg, "enabled": true, "username": "reader", "password": "secret-for-test"})
	if err != nil {
		t.Fatal(err)
	}
	w := request("POST", "/api/purple/sources", string(body))
	if w.Code != 201 || strings.Contains(w.Body.String(), "secret-for-test") {
		t.Fatalf("save multi-stream source: %d %s", w.Code, w.Body)
	}
	var source db.SecuritySource
	if err := json.Unmarshal(w.Body.Bytes(), &source); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
	if len(source.Config.Streams) != 3 || source.Config.Streams[1].Index != "ag_vuln_bank" || source.Config.Streams[1].Asset != "vuln-bank" {
		t.Fatalf("saved streams changed: %+v", source.Config.Streams)
	}
	stored, err := s.m.pg.GetSecuritySource(t.Context(), source.ID)
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/purple/sources/%d", source.ID)
	for _, index := range []string{"-1", "3", "bad"} {
		w = request("POST", path+"/streams/"+index+"/test", "")
		if w.Code != 400 {
			t.Fatalf("invalid stream %q: %d %s", index, w.Code, w.Body)
		}
	}
	update, err := json.Marshal(map[string]any{"name": "multi-index", "config": cfg, "enabled": true, "expected_revision": source.Revision})
	if err != nil {
		t.Fatal(err)
	}
	w = request("PUT", path, string(update))
	if w.Code != 200 {
		t.Fatalf("unchanged save: %d %s", w.Code, w.Body)
	}
	var same db.SecuritySource
	if err := json.Unmarshal(w.Body.Bytes(), &same); err != nil {
		t.Fatal(err)
	}
	if same.Revision != source.Revision {
		t.Fatalf("unchanged source incremented revision: %d -> %d", source.Revision, same.Revision)
	}
	updated, err := s.m.pg.GetSecuritySource(t.Context(), source.ID)
	if err != nil || string(updated.SecretCipher) != string(stored.SecretCipher) {
		t.Fatalf("same-endpoint update changed credentials: %v", err)
	}
	if w = request("GET", "/api/purple/sources", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "ag_vuln_bank") || strings.Contains(w.Body.String(), "secret-for-test") {
		t.Fatalf("list multi-stream source: %d %s", w.Code, w.Body)
	}
}

func TestPurpleSecuritySourceDiscoveryAndStreamProbeAPI(t *testing.T) {
	s, _, request := purpleAPIFixture(t)
	var discoveryCalls, searchCalls atomic.Int32
	var rejectSearch atomic.Bool
	const secret = "test-only-index-reader-token"
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("saved credentials were not used for Splunk request")
		}
		switch r.URL.Path {
		case "/services/data/indexes":
			discoveryCalls.Add(1)
			if r.Method != http.MethodGet || r.URL.Query().Get("count") != "128" {
				t.Errorf("unexpected index discovery request: %s %s", r.Method, r.URL)
			}
			_, _ = w.Write([]byte(`{"entry":[{"name":"ag_vuln_bank"},{"name":"ag_juice_shop"}]}`))
		case "/services/search/v2/jobs/export":
			searchCalls.Add(1)
			if r.Method != http.MethodPost {
				t.Errorf("unexpected stream probe method: %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			query := r.FormValue("search")
			if !strings.Contains(query, `index="ag_vuln_bank"`) || !strings.Contains(query, `sourcetype="web_access"`) || !strings.Contains(query, "| head 1") || strings.Contains(query, "ag_juice_shop") {
				t.Errorf("probe selected wrong configured stream: %s", query)
			}
			if r.FormValue("earliest_time") == "" || r.FormValue("latest_time") == "" {
				t.Error("probe has no bounded search window")
			}
			if rejectSearch.Load() {
				http.Error(w, "private-upstream-secret", http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte("{\"preview\":false,\"lastrow\":true}\n"))
		default:
			t.Errorf("unexpected Splunk endpoint: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer remote.Close()
	pin := sha256.Sum256(remote.Certificate().Raw)
	cfg := securitysource.Config{
		BaseURL: remote.URL, CorrelationField: "artex_verification_id", ActionField: "action", TLSFingerprint: hex.EncodeToString(pin[:]),
		Streams: []securitysource.LogStream{
			{Index: "ag_juice_shop", Sourcetype: "web_access", Kind: "audit"},
			{Index: "ag_vuln_bank", Sourcetype: "web_access", Kind: "audit"},
			{Index: "ag_alerts", Sourcetype: "notable", Kind: "alert"},
		},
	}
	cipher, err := s.encryptSourceCredentials(securitysource.Credentials{Token: secret})
	if err != nil {
		t.Fatal(err)
	}
	source, err := s.m.pg.SaveSecuritySource(t.Context(), 0, 0, "probe test", cfg, true, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
	base := fmt.Sprintf("/api/purple/sources/%d", source.ID)
	w := request("GET", base+"/indexes", "")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || discoveryCalls.Load() != 1 || strings.Contains(w.Body.String(), secret) {
		t.Fatalf("index discovery: %d %s", w.Code, w.Body)
	}
	var discovered struct {
		Indexes []string `json:"indexes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &discovered); err != nil || len(discovered.Indexes) != 2 || discovered.Indexes[0] != "ag_juice_shop" || discovered.Indexes[1] != "ag_vuln_bank" {
		t.Fatalf("discovered indexes: %+v %v", discovered, err)
	}
	w = request("POST", base+"/streams/1/test", "")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || searchCalls.Load() != 1 {
		t.Fatalf("stream probe: %d %s", w.Code, w.Body)
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["ok"] != true || result["searchable"] != true || result["has_recent_events"] != false || result["index"] != "ag_vuln_bank" || result["sourcetype"] != "web_access" || result["kind"] != "audit" {
		t.Fatalf("unexpected completed zero-event probe: %+v", result)
	}
	rejectSearch.Store(true)
	w = request("POST", base+"/streams/1/test", "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "private-upstream-secret") || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), remote.URL) {
		t.Fatalf("upstream error was not redacted: %d %s", w.Code, w.Body)
	}
}

func TestPurpleSecuritySourceAuthentication(t *testing.T) {
	s := &Server{jwtKey: []byte("key")}
	for _, r := range []struct{ method, path string }{{"GET", "/api/purple/sources"}, {"POST", "/api/purple/sources"}, {"PUT", "/api/purple/sources/1"}, {"DELETE", "/api/purple/sources/1"}, {"POST", "/api/purple/sources/1/test"}, {"GET", "/api/purple/sources/1/indexes"}, {"POST", "/api/purple/sources/1/streams/0/test"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(r.method, r.path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatalf("unprotected %s", r.path)
		}
	}
}
