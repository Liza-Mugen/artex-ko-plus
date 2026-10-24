package hunting

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// ErrResearchUnresolved preserves collected literature without permitting the
// caller to treat an ambiguous name or an unrelated page as a scenario basis.
var ErrResearchUnresolved = errors.New("공개 자료에서 조사 대상을 충분히 식별하지 못했습니다")

const (
	researchMaxCandidates = 16
	researchMaxBody       = 1 << 20
	researchMaxExcerpt    = 12000
	researchTimeout       = 40 * time.Second
)

type ResearchResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// Researcher only reads public text. Search is supplied by the existing web
// search adapter; nil means that only the explicitly supplied URLs are read.
// HTTPClient and Resolver are trusted application/test dependencies, never user
// request fields. Non-standard RoundTrippers must enforce their own connection
// routing; standard transports are rebuilt with public-IP-pinned dialing.
type Researcher struct {
	Search     func(context.Context, string) ([]string, error)
	HTTPClient *http.Client
	Resolver   ResearchResolver
	Now        func() time.Time
}

// Semantic document boundaries are kept only during collection. In particular,
// one advisory in a vendor's annual archive must not absorb adjacent advisories.
type researchDocument struct {
	ResearchSource
	Articles []string
	Mains    []string
}

var researchCVE = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)

func (r Researcher) Run(ctx context.Context, request Request) (Research, error) {
	term := strings.TrimSpace(request.Term)
	out := Research{Term: term, CVEs: []string{}, Sources: []ResearchSource{}, Claims: []ResearchClaim{}, Warnings: []string{}}
	if utf8.RuneCountInString(term) < 2 || utf8.RuneCountInString(term) > 300 || strings.ContainsAny(term, "\x00\r\n") || !utf8.ValidString(term) || len(request.ResearchURLs) > MaxResearchSources {
		return out, fmt.Errorf("%w: 취약점 이름과 공개 자료 URL 수를 확인해 주세요", ErrInvalid)
	}
	requestedCVEs := researchCVEs(term)
	if len(requestedCVEs) > 1 || researchGenericName(term) {
		out.Summary = "제품·버전 또는 단일 취약점 식별자를 더 구체적으로 지정해야 합니다."
		return out, ErrResearchUnresolved
	}
	ctx, cancel := context.WithTimeout(ctx, researchTimeout)
	defer cancel()
	client := r.client()
	defer client.CloseIdleConnections()
	seen := map[string]bool{}
	relevantCVEs := map[string]bool{}
	for _, cve := range requestedCVEs {
		relevantCVEs[cve] = true
	}
	documents := []researchDocument{}
	accepted := map[string]bool{}
	consider := func() {
		// A registry/vendor page can omit a popular alias. Keep fetched pages
		// locally and revisit them when an alias-bearing document identifies CVEs.
		// Only the alias-bearing literature may expand that identity set; nearby
		// unrelated CVEs on a registry/archive page cannot expand it transitively.
		for _, document := range documents {
			if accepted[document.URL] || len(out.Sources) >= MaxResearchSources {
				continue
			}
			needle := term
			direct := researchMentions(document.Title+" "+document.Excerpt, term)
			if !direct {
				needle = ""
				for _, cve := range researchCVEs(document.Title + " " + document.Excerpt) {
					if relevantCVEs[cve] {
						needle = cve
						break
					}
				}
				if needle == "" {
					continue
				}
			}
			selected, structured := researchSelectDocument(document, term, relevantCVEs)
			identifiers := researchSubjectCVEs(selected.Excerpt, term)
			if direct && structured {
				identifiers = researchCVEs(selected.Excerpt)
			}
			accepted[document.URL] = true
			source := researchSnapshot(selected, needle, identifiers)
			out.Sources = append(out.Sources, source)
			claim := researchRelevantExcerpt(source.Excerpt, needle, 900)
			out.Claims = append(out.Claims, ResearchClaim{Text: claim, SourceIDs: []string{source.ID}})
			if direct {
				for _, cve := range identifiers {
					if researchMentions(source.Excerpt, cve) {
						relevantCVEs[cve] = true
					}
				}
			}
		}
	}
	read := func(candidates []string) {
		// Explicit URLs retain their order. Search results put recognized vendor
		// and vulnerability registries first, without treating priority as proof.
		for _, candidate := range candidates {
			if len(seen) >= researchMaxCandidates || len(out.Sources) >= MaxResearchSources || ctx.Err() != nil {
				return
			}
			u, err := researchURL(candidate)
			if err != nil {
				out.Warnings = append(out.Warnings, "공개 HTTP(S) 자료가 아닌 URL을 제외했습니다.")
				continue
			}
			key := u.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			source, err := r.fetch(ctx, client, u)
			if err != nil {
				out.Warnings = append(out.Warnings, "일부 공개 자료를 가져오지 못했습니다: "+researchPublicError(err))
				continue
			}
			documents = append(documents, source)
			consider()
			consider() // newly identified CVEs may admit an earlier vendor page
		}
	}
	read(request.ResearchURLs)
	if r.Search == nil {
		out.Warnings = append(out.Warnings, "웹 검색 연결이 없어 직접 지정한 공개 자료만 확인했습니다.")
	} else {
		queries := []string{term + " vulnerability security advisory affected versions", term + " technical analysis proof of concept detection"}
		for index := 0; index < len(queries) && index < 3; index++ {
			if ctx.Err() != nil || len(out.Sources) >= MaxResearchSources || len(seen) >= researchMaxCandidates {
				break
			}
			urls, err := r.Search(ctx, queries[index])
			if err != nil {
				out.Warnings = append(out.Warnings, "공개 자료 검색을 완료하지 못했습니다. 직접 확인할 자료 URL을 지정할 수 있습니다.")
			} else {
				if len(urls) > researchMaxCandidates {
					urls = urls[:researchMaxCandidates]
				}
				urls = append([]string(nil), urls...)
				sort.SliceStable(urls, func(i, j int) bool { return researchPriority(urls[i]) < researchPriority(urls[j]) })
				read(urls)
			}
			if index == 1 && len(requestedCVEs) == 0 && len(relevantCVEs) > 0 {
				ids := []string{}
				for cve := range relevantCVEs {
					ids = append(ids, cve)
				}
				sort.Strings(ids)
				if len(ids) > 4 {
					ids = ids[:4]
				}
				queries = append(queries, strings.Join(ids, " ")+" official vendor security advisory affected versions")
			}
		}
	}
	for cve := range relevantCVEs {
		out.CVEs = append(out.CVEs, cve)
	}
	sort.Strings(out.CVEs)
	out.Warnings = append(out.Warnings, "문헌과 PoC는 정적으로 읽었습니다. 출처의 주장은 실제 대상의 영향·악용·재현 성공을 독립적으로 증명하지 않습니다.")
	if len(documents) > len(out.Sources) {
		out.Warnings = append(out.Warnings, "입력한 이름·연관 식별자가 원문에서 확인되지 않는 자료를 제외했습니다.")
	}
	sort.SliceStable(out.Sources, func(i, j int) bool {
		return researchPriority(out.Sources[i].URL) < researchPriority(out.Sources[j].URL)
	})
	out.Warnings = researchUnique(out.Warnings)
	if ctx.Err() != nil {
		out.Summary = "공개 자료 조사 한도에 도달했습니다. 확보한 자료를 보존했습니다."
		return out, ctx.Err()
	}
	if len(out.Sources) == 0 {
		out.Summary = "입력한 취약점과 연결되는 공개 원문을 확보하지 못했습니다. 정확한 CVE 또는 공식 자료 URL이 필요합니다."
		return out, ErrResearchUnresolved
	}
	if len(requestedCVEs) == 1 {
		out.CVEs = requestedCVEs
	} else if len(out.CVEs) > 1 {
		out.Warnings = append(out.Warnings, "관련 문헌에 여러 CVE가 함께 기재돼 있습니다. 하나의 취약점으로 합치지 말고 영향 조건과 근거를 식별자별로 구분해야 합니다.")
	}
	if len(out.CVEs) == 0 {
		out.Warnings = append(out.Warnings, "관련 이름은 원문에서 확인했지만 CVE 식별자는 확인하지 못했습니다.")
	}
	out.Summary = fmt.Sprintf("%s 관련 공개 원문 %d개를 확보했습니다. 보존된 문헌 주장을 바탕으로 조사 가설을 설계할 수 있으며 실제 악용 여부는 별도 로그 근거로 확인해야 합니다.", term, len(out.Sources))
	return out, nil
}

func (r Researcher) resolver() ResearchResolver {
	if r.Resolver != nil {
		return r.Resolver
	}
	return net.DefaultResolver
}

func researchURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n") {
		return nil, ErrInvalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" || u.Scheme != "https" && u.Scheme != "http" {
		return nil, ErrInvalid
	}
	port := u.Port()
	if port != "" && (u.Scheme == "https" && port != "443" || u.Scheme == "http" && port != "80") {
		return nil, ErrInvalid
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if strings.Contains(host, "%") || host == "localhost" || strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") && net.ParseIP(host) == nil {
		return nil, ErrInvalid
	}
	for _, suffix := range []string{".local", ".internal", ".lan", ".home", ".test", ".invalid"} {
		if strings.HasSuffix(host, suffix) {
			return nil, ErrInvalid
		}
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	return u, nil
}

var researchReserved = func() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		prefixes = append(prefixes, netip.MustParsePrefix(raw))
	}
	return prefixes
}()

func researchPublicIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() {
		return false
	}
	for _, prefix := range researchReserved {
		if prefix.Contains(a) {
			return false
		}
	}
	return !a.Is6() || netip.MustParsePrefix("2000::/3").Contains(a)
}

func (r Researcher) addresses(ctx context.Context, host string) ([]net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !researchPublicIP(ip) {
			return nil, fmt.Errorf("public address required")
		}
		return []net.IPAddr{{IP: ip}}, nil
	}
	rows, err := r.resolver().LookupIPAddr(ctx, host)
	if err != nil || len(rows) == 0 || len(rows) > 32 {
		return nil, fmt.Errorf("public DNS resolution failed")
	}
	for _, row := range rows {
		if row.Zone != "" || !researchPublicIP(row.IP) {
			return nil, fmt.Errorf("public address required")
		}
	}
	return rows, nil
}

func (r Researcher) client() *http.Client {
	client := http.Client{Timeout: 8 * time.Second}
	if r.HTTPClient != nil {
		client = *r.HTTPClient
		if client.Timeout <= 0 || client.Timeout > 8*time.Second {
			client.Timeout = 8 * time.Second
		}
	}
	client.Jar = nil
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("redirect limit")
		}
		u, err := researchURL(req.URL.String())
		if err != nil || len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("unsafe redirect")
		}
		if _, err = r.addresses(req.Context(), u.Hostname()); err != nil {
			return fmt.Errorf("unsafe redirect")
		}
		// Never forward response-set cookies or authentication across sources.
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		req.Header.Del("Referer")
		return nil
	}
	var transport *http.Transport
	if client.Transport == nil {
		if existing, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = existing.Clone()
		} else {
			transport = &http.Transport{}
		}
	} else if existing, ok := client.Transport.(*http.Transport); ok {
		transport = existing.Clone()
	}
	if transport != nil {
		transport.Proxy = nil // public research never uses target/recording proxies
		transport.Dial, transport.DialTLS, transport.DialTLSContext = nil, nil, nil
		transport.DisableCompression = true
		transport.ResponseHeaderTimeout = 5 * time.Second
		transport.MaxResponseHeaderBytes = 32 << 10
		if transport.TLSClientConfig != nil {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		} else {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		transport.TLSClientConfig.InsecureSkipVerify = false
		transport.TLSClientConfig.ServerName = ""
		transport.TLSClientConfig.Certificates = nil
		transport.TLSClientConfig.GetClientCertificate = nil
		transport.TLSClientConfig.KeyLogWriter = nil
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "80" && port != "443" {
				return nil, fmt.Errorf("public address required")
			}
			rows, err := r.addresses(ctx, host)
			if err != nil {
				return nil, err
			}
			dialer := net.Dialer{Timeout: 3 * time.Second}
			for _, row := range rows {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(row.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
			}
			return nil, fmt.Errorf("public connection failed")
		}
		client.Transport = transport
	}
	return &client
}

func (r Researcher) fetch(ctx context.Context, client *http.Client, u *url.URL) (researchDocument, error) {
	if _, err := r.addresses(ctx, u.Hostname()); err != nil {
		return researchDocument{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return researchDocument{}, err
	}
	req.Header.Set("User-Agent", "AegisLoop-PublicResearch/1.0")
	req.Header.Set("Accept", "text/html, text/plain, text/markdown, application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return researchDocument{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > researchMaxBody {
		return researchDocument{}, fmt.Errorf("response status or size")
	}
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && encoding != "identity" {
		return researchDocument{}, fmt.Errorf("unsupported encoding")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, researchMaxBody+1))
	if err != nil || len(body) > researchMaxBody || !utf8.Valid(body) || strings.IndexByte(string(body), 0) >= 0 {
		return researchDocument{}, fmt.Errorf("response text or size")
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(body)
	}
	kind, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8") && !strings.EqualFold(params["charset"], "us-ascii") {
		return researchDocument{}, fmt.Errorf("unsupported text encoding")
	}
	title, text := "", string(body)
	var articles, mains []string
	switch kind {
	case "text/html", "application/xhtml+xml":
		title, text, articles, mains = researchHTMLDocument(text)
	case "text/plain", "text/markdown", "text/x-markdown", "application/json":
	default:
		return researchDocument{}, fmt.Errorf("unsupported content type")
	}
	text = strings.Join(strings.Fields(text), " ")
	if len(text) < 40 {
		return researchDocument{}, fmt.Errorf("insufficient source text")
	}
	// Full bounded text stays local to Run until its subject is identified.
	// researchSnapshot retains and hashes only the selected subject window.
	title = researchClip(strings.Join(strings.Fields(title), " "), 300)
	if title == "" {
		title = researchClip(u.Hostname()+u.EscapedPath(), 300)
	}
	finalURL := u.String()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	hash := sha256.Sum256([]byte(text))
	identifier := sha256.Sum256([]byte(finalURL + "\x00" + text))
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	return researchDocument{ResearchSource: ResearchSource{ID: "research-" + hex.EncodeToString(identifier[:8]), URL: finalURL, Title: title, Excerpt: text, SHA256: hex.EncodeToString(hash[:]), FetchedAt: now}, Articles: articles, Mains: mains}, nil
}

func researchSnapshot(source ResearchSource, needle string, identifiers []string) ResearchSource {
	text := source.Excerpt
	source.Excerpt = researchRelevantExcerpt(text, needle, researchMaxExcerpt)
	// An article can describe a vulnerability family in a later table. Preserve
	// each identified CVE's actual context within the same bounded snapshot,
	// rather than listing identifiers whose evidence was discarded by clipping.
	missing := false
	for _, id := range identifiers {
		missing = missing || !researchMentions(source.Excerpt, id)
	}
	if missing {
		source.Excerpt = researchRelevantExcerpt(text, needle, researchMaxExcerpt/3)
		for _, id := range identifiers {
			if researchMentions(source.Excerpt, id) {
				continue
			}
			remaining := researchMaxExcerpt - len(source.Excerpt) - len("\n[…]\n")
			if remaining < len(id)+32 {
				break
			}
			source.Excerpt += "\n[…]\n" + researchRelevantExcerpt(text, id, min(1800, remaining))
		}
	}
	hash := sha256.Sum256([]byte(source.Excerpt))
	identifier := sha256.Sum256([]byte(source.URL + "\x00" + source.Excerpt))
	source.SHA256 = hex.EncodeToString(hash[:])
	source.ID = "research-" + hex.EncodeToString(identifier[:8])
	return source
}

func researchHTML(body string) (string, string) {
	title, text, _, _ := researchHTMLDocument(body)
	return title, text
}

func researchHTMLDocument(body string) (title, text string, articles, mains []string) {
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return "", "", nil, nil
	}
	root := document
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if researchSkipNode(node) {
			return
		}
		if node.Type == html.ElementNode {
			switch node.Data {
			case "title":
				title = researchNodeText(node)
			case "body":
				root = node
			case "article":
				articles = append(articles, researchNodeText(node))
			case "main":
				mains = append(mains, researchNodeText(node))
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document)
	return title, researchNodeText(root), articles, mains
}

func researchSkipNode(node *html.Node) bool {
	if node.Type != html.ElementNode {
		return false
	}
	switch node.Data {
	case "script", "style", "noscript", "svg", "template", "nav", "footer", "aside":
		return true
	}
	for _, attribute := range node.Attr {
		if attribute.Key == "hidden" || attribute.Key == "aria-hidden" && attribute.Val == "true" {
			return true
		}
	}
	return false
}

func researchNodeText(node *html.Node) string {
	var text strings.Builder
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if researchSkipNode(node) {
			return
		}
		if node.Type == html.TextNode {
			text.WriteString(node.Data)
			text.WriteByte(' ')
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(node)
	return strings.Join(strings.Fields(text.String()), " ")
}

func researchSelectDocument(document researchDocument, term string, knownCVEs map[string]bool) (ResearchSource, bool) {
	selectText := func(candidates []string) string {
		best, bestScore, longest := "", -1, ""
		for _, text := range candidates {
			if len(text) > len(longest) {
				longest = text
			}
		}
		titleNamesSubject := researchMentions(document.Title, term)
		for _, text := range candidates {
			if len(text) < 40 || titleNamesSubject && len(text) < len(longest)/4 {
				continue // omit related-story cards beside the full article
			}
			matches, subject := 0, researchMentions(text, term)
			for _, id := range researchCVEs(text) {
				if knownCVEs[id] {
					matches++
				}
			}
			if !subject && matches == 0 {
				continue
			}
			score := matches * (researchMaxBody + 1)
			if subject {
				score += researchMaxBody + 1
			}
			score += len(text)
			if score > bestScore {
				best, bestScore = text, score
			}
		}
		if best == "" && titleNamesSubject && len(longest) >= 40 {
			best = longest
		}
		return best
	}
	source := document.ResearchSource
	if text := selectText(document.Articles); text != "" {
		source.Excerpt = text
		return source, true
	}
	if text := selectText(document.Mains); text != "" {
		source.Excerpt = text
		// A <main> containing multiple articles is an archive, not one subject.
		// Without article children it is the page's semantic document boundary.
		return source, len(document.Articles) == 0
	}
	return source, false
}

func researchClip(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}

func researchRelevantExcerpt(text, term string, limit int) string {
	if len(text) <= limit {
		return text
	}
	position := researchTermPosition(text, term)
	if term == "" || position < 0 {
		return researchClip(text, limit)
	}
	start := max(0, position-limit/4)
	for start > 0 && !utf8.RuneStart(text[start]) {
		start--
	}
	return researchClip(text[start:], limit)
}

func researchMentions(text, term string) bool {
	if ids := researchCVEs(term); len(ids) == 1 && strings.EqualFold(strings.TrimSpace(term), ids[0]) {
		for _, found := range researchCVEs(text) {
			if found == ids[0] {
				return true
			}
		}
		return false
	}
	return researchTermPosition(text, term) >= 0
}

func researchTermPosition(text, term string) int {
	pattern := researchTermPattern(term)
	if pattern == nil {
		return -1
	}
	indices := pattern.FindStringSubmatchIndex(text)
	if len(indices) < 4 {
		return -1
	}
	return indices[2]
}

func researchTermPattern(term string) *regexp.Regexp {
	parts := strings.FieldsFunc(term, func(c rune) bool { return !unicode.IsLetter(c) && !unicode.IsDigit(c) })
	if len(parts) == 0 {
		return nil
	}
	for index := range parts {
		parts[index] = regexp.QuoteMeta(parts[index])
	}
	return regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}])(` + strings.Join(parts, `[^\p{L}\p{N}]+`) + `)(?:$|[^\p{L}\p{N}])`)
}

func researchSubjectCVEs(text, term string) []string {
	pattern := researchTermPattern(term)
	if pattern == nil {
		return nil
	}
	var ids []string
	for _, indices := range pattern.FindAllStringSubmatchIndex(text, 16) {
		// Repeated body mentions matter: a title can precede long navigation.
		// Identifiers elsewhere on an unrelated footer are not automatically
		// evidence that this alias names those vulnerabilities.
		start, end := max(0, indices[2]-300), min(len(text), indices[3]+2200)
		ids = append(ids, researchCVEs(text[start:end])...)
	}
	return researchUnique(ids)
}

func researchCVEs(text string) []string {
	return researchUnique(researchCVE.FindAllString(strings.ToUpper(text), -1))
}

func researchGenericName(term string) bool {
	switch strings.ToLower(strings.TrimSpace(term)) {
	case "cve", "rce", "xss", "sqli", "php", "취약점", "vulnerability", "vulnerabilities", "exploit", "漏洞":
		return true
	}
	return false
}

func researchUnique(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func researchPriority(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 2
	}
	host := strings.ToLower(u.Hostname())
	for _, primary := range []string{"php.net", "cve.org", "nvd.nist.gov", "msrc.microsoft.com", "access.redhat.com", "ubuntu.com", "security.debian.org", "apache.org", "openssl.org", "cisco.com", "fortiguard.com"} {
		if host == primary || strings.HasSuffix(host, "."+primary) {
			return 0
		}
	}
	if host == "github.com" && strings.HasPrefix(u.Path, "/advisories/") {
		return 0
	}
	return 1
}

func researchPublicError(err error) string {
	// Network errors may contain complete URLs, proxy metadata or response
	// content. Public traces retain a category only.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "시간 한도 또는 취소"
	}
	return "공개 주소·연결·응답 형식·크기 확인 필요"
}
