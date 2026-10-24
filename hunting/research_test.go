package hunting

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type researchResolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f researchResolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type researchRoundTripFunc func(*http.Request) (*http.Response, error)

func (f researchRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func researchFixture(t *testing.T, body string) (Researcher, *[]string) {
	t.Helper()
	requests := []string{}
	r := Researcher{
		Resolver: researchResolverFunc(func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		}),
		HTTPClient: &http.Client{Transport: researchRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests = append(requests, req.URL.String())
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: req}, nil
		})},
		Now: func() time.Time { return time.Date(2026, 10, 24, 3, 0, 0, 0, time.UTC) },
	}
	return r, &requests
}

func TestResearchPublicSourcesRetainStaticLiterature(t *testing.T) {
	body := `<html><title>ExampleShell advisory</title><script>execute-this-never()</script><style>secret-style</style><body>ExampleShell is described as CVE-2026-12345. The vendor states affected versions and prerequisite configuration. A proof of concept is provided for static review only.</body></html>`
	r, requests := researchFixture(t, body)
	result, err := r.Run(context.Background(), Request{Term: "ExampleShell", ResearchURLs: []string{"https://advisory.example.com/security#part", "https://advisory.example.com/security"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 || len(result.Sources) != 1 || len(result.Claims) != 1 || len(result.CVEs) != 1 || result.CVEs[0] != "CVE-2026-12345" {
		t.Fatalf("unexpected research: requests=%v result=%+v", *requests, result)
	}
	source := result.Sources[0]
	if source.URL != "https://advisory.example.com/security" || source.Title != "ExampleShell advisory" || source.FetchedAt != r.Now() {
		t.Fatalf("incorrect source snapshot: %+v", source)
	}
	hash := sha256.Sum256([]byte(source.Excerpt))
	if source.SHA256 != hex.EncodeToString(hash[:]) || strings.Contains(source.Excerpt, "execute-this") || strings.Contains(source.Excerpt, "secret-style") {
		t.Fatalf("source text/hash mismatch: %+v", source)
	}
	if len(result.Claims[0].SourceIDs) != 1 || result.Claims[0].SourceIDs[0] != source.ID || !strings.Contains(source.Excerpt, result.Claims[0].Text) {
		t.Fatalf("claim is not retained source text: %+v", result.Claims)
	}
	if !strings.Contains(strings.Join(result.Warnings, " "), "정적으로") {
		t.Fatal("literature must not be presented as reproduction")
	}
}

func TestResearchSearchIsBoundedAndPrioritizesPrimarySources(t *testing.T) {
	r, requests := researchFixture(t, `<title>CVE-2026-12345</title><p>CVE-2026-12345 describes a vulnerability and the necessary affected configuration, not a confirmed incident.</p>`)
	queries := []string{}
	r.Search = func(ctx context.Context, query string) ([]string, error) {
		queries = append(queries, query)
		return []string{"https://analysis.example.com/post", "https://www.php.net/security/advisory", "https://nvd.nist.gov/vuln/detail/CVE-2026-12345", "https://analysis.example.com/post"}, nil
	}
	result, err := r.Run(context.Background(), Request{Term: "CVE-2026-12345"})
	if err != nil {
		t.Fatal(err)
	}
	if len(queries) != 2 || len(*requests) != 3 || (*requests)[0] != "https://www.php.net/security/advisory" || (*requests)[1] != "https://nvd.nist.gov/vuln/detail/CVE-2026-12345" || len(result.Sources) != 3 {
		t.Fatalf("search bounds/priority: queries=%v requests=%v result=%+v", queries, *requests, result)
	}
}

func TestResearchUnresolvedWithoutRelevantOriginalText(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"no sources", ""},
		{"unrelated original", `<title>Another advisory</title><p>This document discusses another vulnerability with different products and versions.</p>`},
		{"script only", `<title>Unrelated document</title><script>CVE-2026-12345</script><p>The visible text discusses a different subject with no matching identifier.</p>`},
		{"identifier prefix", `<title>CVE-2026-123456</title><p>CVE-2026-123456 is a different identifier, despite sharing a textual prefix with the requested value.</p>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, requests := researchFixture(t, tc.body)
			in := Request{Term: "CVE-2026-12345"}
			if tc.body != "" {
				in.ResearchURLs = []string{"https://advisory.example.com/post"}
			}
			result, err := r.Run(context.Background(), in)
			if !errors.Is(err, ErrResearchUnresolved) || len(result.Sources) != 0 || len(result.Claims) != 0 || tc.body == "" && len(*requests) != 0 {
				t.Fatalf("unrelated/missing source permitted: %+v %v", result, err)
			}
		})
	}
}

func TestResearchBundledCVEsRemainDistinctLiteratureClaims(t *testing.T) {
	r, _ := researchFixture(t, `<title>ExampleShell</title><p>ExampleShell is a name used for CVE-2026-12345 and CVE-2026-54321. These identify different affected versions and conditions.</p>`)
	result, err := r.Run(context.Background(), Request{Term: "ExampleShell", ResearchURLs: []string{"https://advisory.example.com/post"}})
	if err != nil || len(result.Sources) != 1 || len(result.CVEs) != 2 || len(result.Claims) != 1 || !strings.Contains(strings.Join(result.Warnings, " "), "식별자별") {
		t.Fatalf("bundled identity must retain separate CVEs: result=%+v error=%v", result, err)
	}
}

func TestResearchAliasLeadsToOfficialCVEWithoutAlias(t *testing.T) {
	r, requests := researchFixture(t, "unused fixture")
	queries := []string{}
	r.Search = func(ctx context.Context, query string) ([]string, error) {
		queries = append(queries, query)
		return []string{"https://www.php.net/security/advisory", "https://analysis.example.com/exampleshell"}, nil
	}
	r.HTTPClient.Transport = researchRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		*requests = append(*requests, req.URL.String())
		body := `<title>PHP security release</title><p>The security update addresses CVE-2026-12345 and CVE-2026-54321 with distinct affected configurations and patches.</p>`
		if req.URL.Hostname() == "analysis.example.com" {
			body = `<title>ExampleShell technical analysis</title><p>ExampleShell refers to CVE-2026-12345 and CVE-2026-54321, two related vulnerabilities with distinct prerequisite conditions.</p>`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: req}, nil
	})
	result, err := r.Run(context.Background(), Request{Term: "ExampleShell"})
	if err != nil || len(result.Sources) != 2 || len(*requests) != 2 || len(queries) != 3 || !strings.Contains(queries[2], "CVE-2026-12345") || result.Sources[0].URL != "https://www.php.net/security/advisory" {
		t.Fatalf("alias/CVE follow-up or deferred official source lost: queries=%v requests=%v result=%+v error=%v", queries, *requests, result, err)
	}
}

func TestResearchArticlePreservesDistantFamilyCVEsWithoutArchivePollution(t *testing.T) {
	r, _ := researchFixture(t, "unused fixture")
	r.HTTPClient.Transport = researchRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `<title>PHP2Shell technical analysis</title><nav>PHP2Shell index: CVE-2026-999991</nav><main><h1>PHP2Shell</h1><article><h2>Executive summary</h2><p>PHP2Shell describes a family of vulnerabilities. CVE-2026-109618 concerns one prerequisite configuration.</p>` + strings.Repeat(`<p>The report describes prerequisites and mitigation without claiming an actual incident in the user's system.</p>`, 180) + `<table><tr><td>CVE-2026-109619</td><td>A second independently identified issue has different prerequisite conditions.</td></tr></table></article><article><h2>Related reading</h2><p>Another topic CVE-2026-999992 does not identify PHP2Shell.</p></article></main><footer>PHP2Shell archive CVE-2026-999993</footer>`
		if req.URL.Hostname() == "www.php.net" {
			body = `<title>PHP annual news archive</title><main><article><h2>Later informational advisory</h2><p>The old CVE-2026-109619 mitigation remains relevant. This separate issue is CVE-2026-115560 and has its own release cycle.</p></article><article><h2>Critical security advisory</h2><p>The security update addresses CVE-2026-109618 and CVE-2026-109619. Review the different affected configurations and patches for each issue.</p></article></main>`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1, Request: req}, nil
	})
	result, err := r.Run(context.Background(), Request{Term: "php2shell", ResearchURLs: []string{"https://www.php.net/archive/2026.php", "https://analysis.example.com/php2shell"}})
	if err != nil || len(result.CVEs) != 2 || result.CVEs[0] != "CVE-2026-109618" || result.CVEs[1] != "CVE-2026-109619" || len(result.Sources) != 2 {
		t.Fatalf("family or source identity lost: %+v %v", result, err)
	}
	for _, source := range result.Sources {
		if len(source.Excerpt) > researchMaxExcerpt || !utf8.ValidString(source.Excerpt) || !strings.Contains(source.Excerpt, "CVE-2026-109618") || !strings.Contains(source.Excerpt, "CVE-2026-109619") {
			t.Fatalf("CVE context missing from retained snapshot: %+v", source)
		}
		for _, unrelated := range []string{"CVE-2026-115560", "CVE-2026-999991", "CVE-2026-999992", "CVE-2026-999993"} {
			if strings.Contains(source.Excerpt, unrelated) {
				t.Fatalf("adjacent article/navigation polluted source with %s: %+v", unrelated, source)
			}
		}
		hash := sha256.Sum256([]byte(source.Excerpt))
		if source.SHA256 != hex.EncodeToString(hash[:]) {
			t.Fatal("composed retained excerpt hash is invalid")
		}
	}
}

func TestResearchMainDocumentPreservesFamilyCVEs(t *testing.T) {
	body := `<title>FamilyShell advisory</title><nav>FamilyShell index CVE-2026-999991</nav><main><h1>FamilyShell</h1><p>CVE-2026-12345 describes the first issue.</p>` + strings.Repeat(`<p>The advisory explains different prerequisite conditions and affected configurations.</p>`, 180) + `<p>CVE-2026-54321 describes the second distinct issue.</p></main><footer>FamilyShell archive CVE-2026-999992</footer>`
	r, _ := researchFixture(t, body)
	result, err := r.Run(context.Background(), Request{Term: "FamilyShell", ResearchURLs: []string{"https://advisory.example.com/familyshell"}})
	if err != nil || len(result.CVEs) != 2 || len(result.Sources) != 1 || !strings.Contains(result.Sources[0].Excerpt, "CVE-2026-12345") || !strings.Contains(result.Sources[0].Excerpt, "CVE-2026-54321") {
		t.Fatalf("main-document family context lost: %+v %v", result, err)
	}
}

func TestResearchRejectsPrivateAndMixedDNSBeforeHTTP(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1/", "https://[::1]/", "http://10.1.2.3/", "http://169.254.169.254/", "http://100.64.0.1/", "https://[64:ff9b::7f00:1]/", "https://[2002:7f00:1::]/", "https://[2001:db8::1]/", "https://advisory.example.com/post"} {
		t.Run(raw, func(t *testing.T) {
			r, requests := researchFixture(t, "unused fixture")
			r.Resolver = researchResolverFunc(func(ctx context.Context, host string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("192.168.1.1")}}, nil
			})
			result, err := r.Run(context.Background(), Request{Term: "CVE-2026-12345", ResearchURLs: []string{raw}})
			if !errors.Is(err, ErrResearchUnresolved) || len(*requests) != 0 || len(result.Sources) != 0 {
				t.Fatalf("private/mixed destination reached HTTP: %v %+v %v", *requests, result, err)
			}
		})
	}
}

func TestResearchRedirectIsRevalidated(t *testing.T) {
	for _, destination := range []string{"http://127.0.0.1/latest/meta-data", "https://private.example.com/", "http://public.example.com/downgrade"} {
		t.Run(destination, func(t *testing.T) {
			r, _ := researchFixture(t, "unused fixture")
			r.Resolver = researchResolverFunc(func(ctx context.Context, host string) ([]net.IPAddr, error) {
				if host == "private.example.com" {
					return []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}, nil
				}
				return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
			})
			calls := 0
			r.HTTPClient.Transport = researchRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{destination}}, Body: io.NopCloser(strings.NewReader("redirect")), Request: req}, nil
			})
			_, err := r.Run(context.Background(), Request{Term: "CVE-2026-12345", ResearchURLs: []string{"https://advisory.example.com/post"}})
			if !errors.Is(err, ErrResearchUnresolved) || calls != 1 {
				t.Fatalf("unsafe redirect followed: calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestResearchStandardDialRejectsDNSRebindingWithoutConnecting(t *testing.T) {
	r := Researcher{Resolver: researchResolverFunc(func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})}
	client := r.client()
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.DialTLSContext != nil || transport.DialTLS != nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("standard transport must use public pinned dialing and certificate verification")
	}
	conn, err := transport.DialContext(context.Background(), "tcp", "advisory.example.com:443")
	if err == nil || conn != nil {
		t.Fatal("dial connected to rebinding/private destination")
	}
}

func TestResearchRejectsNonTextAndOversizedResponses(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, encoding, body string
	}{
		{"oversized", "text/plain", "", strings.Repeat("x", researchMaxBody+1)},
		{"pdf", "application/pdf", "", "%PDF-CVE-2026-12345"},
		{"gzip", "text/plain", "gzip", "CVE-2026-12345 and source text that should never be decoded by the research reader"},
		{"invalid utf8", "text/plain", "", "CVE-2026-12345 " + string([]byte{0xff})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := researchFixture(t, tc.body)
			r.HTTPClient.Transport = researchRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{tc.contentType}, "Content-Encoding": []string{tc.encoding}}, Body: io.NopCloser(strings.NewReader(tc.body)), ContentLength: -1, Request: req}, nil
			})
			result, err := r.Run(context.Background(), Request{Term: "CVE-2026-12345", ResearchURLs: []string{"https://advisory.example.com/post"}})
			if !errors.Is(err, ErrResearchUnresolved) || len(result.Sources) != 0 {
				t.Fatalf("unsupported body accepted: %+v %v", result, err)
			}
		})
	}
}

func TestResearchRelevantTextBeyondBoilerplateHasValidBoundedHash(t *testing.T) {
	body := `<title>Vendor bulletin</title><p>` + strings.Repeat("일반 사이트 안내 ", 1800) + `CVE-2026-12345 describes a security issue in the configured product. The advisory explains affected versions and remediation.` + `</p>`
	r, _ := researchFixture(t, body)
	result, err := r.Run(context.Background(), Request{Term: "CVE-2026-12345", ResearchURLs: []string{"https://advisory.example.com/post"}})
	if err != nil || len(result.Sources) != 1 {
		t.Fatalf("relevant trailing source text lost: %+v %v", result, err)
	}
	source := result.Sources[0]
	if len(source.Excerpt) > researchMaxExcerpt || !utf8.ValidString(source.Excerpt) || !strings.Contains(source.Excerpt, "CVE-2026-12345") {
		t.Fatalf("invalid bounded excerpt: %d bytes", len(source.Excerpt))
	}
	hash := sha256.Sum256([]byte(source.Excerpt))
	if source.SHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("hash must identify retained text, not discarded body")
	}
}

func TestResearchInputsAndCancellation(t *testing.T) {
	r, requests := researchFixture(t, "unused fixture")
	for _, term := range []string{"", "x", "name\ncommand", strings.Repeat("한", 301)} {
		if _, err := r.Run(context.Background(), Request{Term: term}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid term accepted: %q %v", term, err)
		}
	}
	for _, term := range []string{"PHP", "RCE", "CVE-2026-12345 CVE-2026-54321"} {
		if _, err := r.Run(context.Background(), Request{Term: term}); !errors.Is(err, ErrResearchUnresolved) {
			t.Fatalf("ambiguous term accepted: %q %v", term, err)
		}
	}
	for _, raw := range []string{"file:///etc/passwd", "https://user:password@example.com/", "https://localhost/", "https://server.local/", "https://example.com:8443/", "ftp://example.com/"} {
		if _, err := researchURL(raw); err == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Run(ctx, Request{Term: "ExampleShell", ResearchURLs: []string{"https://advisory.example.com/post"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
	if len(*requests) != 0 {
		t.Fatalf("invalid or cancelled input reached HTTP: %v", *requests)
	}
}
