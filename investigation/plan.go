package investigation

import (
	"fmt"
	"regexp"
	"strings"
)

// BuildPlan uses documented templates. Finding text only selects a family; it
// cannot issue instructions, introduce new URLs, or establish an attack fact.
func BuildPlan(f FindingContext) Plan {
	return BuildPlanWithDefense(f, DefenseGuidanceContext{})
}

// DefenseGuidanceContext holds saved defense records used to contextualize an
// investigation guide. Retest observations and AI scenario drafts remain
// distinct; neither establishes historical intrusion.
type DefenseGuidanceContext struct {
	SuggestedPath       string
	RetestID            int64
	RetestStatus        string
	RetestVerdict       string
	RetestSummary       string
	RetestEvidence      string
	ScenarioState       string
	ScenarioTitle       string
	ScenarioStageTitles []string
	ExecutionID         string
	ExecutionState      string
	ExecutionDetection  string
	ExecutionPrevention string
}

// BuildPlanWithDefense deterministically combines the finding with saved
// defense observations. It does not query a SIEM, invoke an LLM, or interpret
// a successful retest as evidence of an earlier intrusion.
func BuildPlanWithDefense(f FindingContext, defense DefenseGuidanceContext) Plan {
	text := strings.ToLower(f.Name + " " + f.VulnClass + " " + f.Summary + " " + boundedEvidence(f.Evidence))
	if defense.RetestStatus == "completed" && defense.RetestVerdict == "reproduced" {
		text += " " + strings.ToLower(boundedEvidence(defense.RetestSummary)+" "+boundedEvidence(defense.RetestEvidence))
	}
	family := "generic"
	switch {
	case containsAny(text, "ssrf", "server-side request", "서버 측 요청", "서버측 요청"):
		family = "ssrf"
	case containsAny(text, "remote code", "command injection", "코드 실행", "명령 실행", "명령어 삽입") || regexp.MustCompile(`\brce\b`).MatchString(text):
		family = "code_execution"
	case strings.Contains(text, "cwe-209"):
		family = "error_information_exposure"
	case containsAny(text, "authentication", "credential", "인증 우회", "인증 실패", "계정 탈취", "brute force"):
		family = "authentication"
	case errorDisclosure(text):
		family = "error_information_exposure"
	case containsAny(text, "directory", "listing", "디렉터리", "리스팅", "파일 노출", "/ftp", "backup file", "config file") && informationExposure(text):
		family = "file_information_exposure"
	case containsAny(text, "information", "disclosure", "exposure", "directory", "listing", "정보 노출", "정보노출", "리스팅", "파일 노출", "/ftp"):
		family = "information_exposure"
	}
	refs := []Reference{
		{Title: "CTID 취약점 매핑 방법론", URL: "https://ctid.mitre.org/mappings/about/methodology/cve-methodology/"},
		{Title: "NIST SP 800-61r3", URL: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf"},
	}
	base := Hypothesis{ID: "path_access", Title: "취약 경로 접근 흔적", Statement: "취약한 경로가 조사 기간에 요청되었을 수 있습니다. 접근 기록만으로 악용 성공이나 침해를 확정하지 않습니다.", Preconditions: []string{"취약점이 조사 당시에도 해당 자산·경로에 존재했는지 확인"}, RequiredLogs: []string{"웹 서버 또는 리버스 프록시 요청 로그"}, RequiredFields: []string{"시각", "대상 자산", "요청 경로"}, Hunt: "선택한 자산·기간·경로와 일치하는 요청을 찾고, 알려진 ARTEX 검증 요청을 별도 표시합니다.", BenignAlternatives: []string{"관리자·사용자의 정상 접근", "승인된 취약점 점검", "검색 엔진이나 모니터링 요청"}, NextSteps: []string{"당시 노출 여부와 접근 통제 설정 확인", "원본 요청의 메서드·세션·응답과 승인된 점검 일정 대조"}, References: refs}
	if path := safePlanPath(defense.SuggestedPath); path != "" {
		base.Statement = fmt.Sprintf("%s 경로가 조사 기간에 요청되었을 수 있습니다. 접근 기록만으로 악용 성공이나 침해를 확정하지 않습니다.", path)
		base.Hunt = fmt.Sprintf("선택한 자산·기간에서 %s 경로 요청을 찾고, 알려진 ARTEX 검증 요청을 별도 표시합니다.", path)
	}
	hs := []Hypothesis{base}
	switch family {
	case "error_information_exposure":
		hs = append(hs,
			Hypothesis{ID: "error_response", Title: "비정상 요청과 오류 응답", Statement: "취약 조건에 맞는 비정상 요청이 과거에 발생했고 오류 응답이 반환되었을 수 있습니다. 현재 재현 결과를 과거 요청의 사실로 옮기지 않습니다.", Preconditions: []string{"당시 취약한 오류 처리 경로가 배포되어 있었는지 확인", "원본 요청과 응답을 연결할 식별자 확보"}, RequiredLogs: []string{"웹 서버·리버스 프록시 요청/응답 로그", "애플리케이션 예외·오류 로그"}, RequiredFields: []string{"시각", "대상 자산", "요청 경로", "요청 메서드", "Content-Type", "응답 상태 코드", "출발지 또는 요청 ID"}, Hunt: "대상 경로의 비정상 JSON 또는 파싱 오류 요청과 HTTP 5xx 응답을 요청 ID·시간으로 대조합니다. 상태 코드만으로 오류 본문 노출을 확정하지 않습니다.", BenignAlternatives: []string{"잘못된 정상 클라이언트 요청", "승인된 보안 점검·QA", "일시적인 애플리케이션 장애"}, NextSteps: []string{"원본 요청·응답 또는 예외 로그 확보", "동일 출처의 반복 여부와 승인된 점검 일정 확인"}, References: refs},
			Hypothesis{ID: "error_detail_exposure", Title: "오류 페이지·서버 정보 노출", Statement: "오류 응답에 기본 서버 페이지, 배너 또는 내부 연락처가 포함되었을 수 있습니다. 응답 상태 코드만으로 노출 내용을 확인할 수 없습니다.", Preconditions: []string{"해당 요청의 실제 응답 헤더·본문 또는 보존된 프록시 기록 확보", "당시 오류 처리 설정 확인"}, RequiredLogs: []string{"응답 헤더·본문을 보존한 프록시/WAF 기록 또는 트래픽", "웹 서버·애플리케이션 오류 로그"}, RequiredFields: []string{"요청 ID", "시각", "응답 상태 코드", "Server 헤더", "오류 본문 또는 응답 지문", "출발지"}, Hunt: "동일 요청의 정상·오류 응답을 대조해 Server 배너, 기본 오류 페이지와 내부 정보 노출을 확인합니다. 헤더·본문이 수집되지 않았다면 확인 불가로 남깁니다.", BenignAlternatives: []string{"승인된 진단에서 생성한 오류 응답", "모니터링·QA의 오류 확인"}, NextSteps: []string{"당시 응답 원문 또는 장비 보존본 확보", "노출된 정보의 내용과 민감도 평가"}, References: refs},
			Hypothesis{ID: "follow_on_exploration", Title: "오류 정보 이후의 탐색", Statement: "동일 출처가 오류 정보를 본 뒤 주변 경로·메서드·Content-Type을 바꾸어 탐색했을 수 있습니다. 시간 근접이나 같은 IP만으로 동일 행위자·후속 악용을 확정하지 않습니다.", Preconditions: []string{"오류 응답 노출 자체를 원본 근거로 확인", "세션·요청 ID 또는 신뢰할 수 있는 출발지 식별자 확보"}, RequiredLogs: []string{"웹/프록시 접근 로그", "WAF·봇 탐지 로그"}, RequiredFields: []string{"시각", "출발지", "세션 또는 요청 ID", "경로", "요청 메서드", "Content-Type", "상태 코드", "User-Agent"}, Hunt: "노출 요청 전후의 경로·메서드·Content-Type 변화를 같은 로그 출처와 세션으로 대조하고 ARTEX 검증 트래픽을 분리합니다.", BenignAlternatives: []string{"정상 API 클라이언트 재시도", "승인된 취약점 점검", "공유 프록시·NAT의 다른 사용자"}, NextSteps: []string{"세션·요청 상관 ID로 흐름 검토", "후속 요청의 실제 영향은 별도 근거로 평가"}, References: refs},
		)
		// Content-Type and malformed JSON are useful only when the finding or
		// completed retest actually identifies a JSON parsing trigger.
		if !containsAny(text, "json", "파싱", "parser", "parse error") {
			hs[1].RequiredFields = []string{"시각", "대상 자산", "요청 경로", "요청 메서드", "응답 상태 코드", "출발지 또는 요청 ID"}
			hs[1].Hunt = "대상 경로에서 오류를 일으킨 요청과 HTTP 5xx 응답을 요청 ID·시간으로 대조합니다. 상태 코드만으로 오류 본문 노출을 확정하지 않습니다."
			hs[3].Statement = "동일 출처가 오류 정보를 본 뒤 주변 경로·메서드·입력값을 바꾸어 탐색했을 수 있습니다. 시간 근접이나 같은 IP만으로 동일 행위자·후속 악용을 확정하지 않습니다."
			hs[3].RequiredFields = []string{"시각", "출발지", "세션 또는 요청 ID", "경로", "요청 메서드", "상태 코드", "User-Agent"}
			hs[3].Hunt = "노출 요청 전후의 경로·메서드·입력값 변화를 같은 로그 출처와 세션으로 대조하고 ARTEX 검증 트래픽을 분리합니다."
		}
	case "file_information_exposure":
		hs = append(hs, Hypothesis{ID: "multi_path", Title: "여러 하위 파일에 대한 요청 흐름", Statement: "동일한 로그 출처의 동일 세션 또는 출발지에서 짧은 시간 동안 여러 하위 경로를 요청했을 수 있습니다. 동일 IP는 동일 공격자를 뜻하지 않습니다.", Preconditions: []string{"대상 경로에 여러 파일 또는 하위 자원이 존재", "세션 또는 출발지 필드가 실제 요청 로그에 존재"}, RequiredLogs: []string{"경로별 웹 요청 로그", "전송 완료·응답 바이트 로그"}, RequiredFields: []string{"시각", "요청 경로", "세션 또는 출발지", "대상 자산"}, Hunt: "동일 파일 출처·세션(없으면 출발지)에서 10분 이내 서로 다른 하위 경로 2개 이상이 관측되는지 확인합니다. 경보 중복을 요청 수로 세지 않습니다.", BenignAlternatives: []string{"정상 브라우저의 여러 리소스 로딩", "공유 프록시·NAT", "허가된 수집·백업 작업"}, NextSteps: []string{"요청된 파일 내용과 민감도 확인", "전송 완료·바이트·인증 상태를 확인하여 실제 전달 범위 판단"}, References: refs}, Hypothesis{ID: "exposed_credentials", Title: "노출 정보의 후속 악용 여부", Statement: "노출된 파일에 당시 유효한 자격증명이 실제 포함되어 있었다면 해당 계정의 후속 사용을 조사할 필요가 있습니다.", Preconditions: []string{"노출된 파일의 실제 내용에서 자격증명 확인", "그 자격증명이 조사 당시 유효했는지 확인", "계정 식별자와 인증 로그 확보"}, RequiredLogs: []string{"당시 파일 내용 또는 보존본", "인증·계정 감사 로그"}, RequiredFields: []string{"계정", "인증 시각", "인증 결과", "세션", "출발지"}, Hunt: "확인된 계정을 기준으로 로그인과 권한 변경을 대조합니다. 정보 노출이나 같은 IP만으로 계정 탈취를 추정하지 않습니다.", BenignAlternatives: []string{"계정 소유자의 정상 사용", "이미 폐기된 예시 자격증명"}, NextSteps: []string{"파일 보존본과 인증 로그 확보", "계정 담당자와 활동의 승인 여부 확인"}, References: refs})
	case "authentication":
		hs = append(hs, Hypothesis{ID: "account_misuse", Title: "인증 우회·계정 사용 조사", Statement: "인증 취약점이 실제 악용되었다면 정상 인증 흐름과 다른 세션 발급·권한 사용 흔적이 남았을 수 있습니다.", Preconditions: []string{"취약 인증 경로와 필요한 조건 확인", "계정·세션 감사 로그 확보"}, RequiredLogs: []string{"인증 성공·실패 로그", "세션 발급 및 권한 변경 로그"}, RequiredFields: []string{"계정", "세션", "시각", "인증 결과", "권한"}, Hunt: "취약 경로 요청과 계정 활동을 실제 세션·계정 식별자로 대조하고 승인 여부를 확인합니다.", BenignAlternatives: []string{"정상 로그인 재시도", "SSO·서비스 계정 활동"}, NextSteps: []string{"인증 로그 확보 후 계정 담당자 확인", "권한 변경의 승인 기록 대조"}, References: refs})
	case "code_execution":
		hs = append(hs, Hypothesis{ID: "host_execution", Title: "후속 프로세스·지속성 흔적 조사", Statement: "서버에서 코드가 실제 실행되었다면 웹 프로세스 하위 프로세스와 파일·네트워크 활동을 조사해야 합니다.", Preconditions: []string{"실행 조건과 영향받는 서버 확인", "호스트 감사 또는 EDR 자료 확보"}, RequiredLogs: []string{"EDR·프로세스 생성 로그", "파일 변경·네트워크 연결 로그"}, RequiredFields: []string{"호스트", "프로세스 ID", "부모 프로세스", "명령행", "시각"}, Hunt: "웹 프로세스의 자식 프로세스와 파일·외부 연결을 호스트 식별자로 대조합니다. HTTP 응답으로 코드 실행 성공을 확정하지 않습니다.", BenignAlternatives: []string{"애플리케이션의 정상 외부 명령 실행", "배포·백업·관리 작업"}, NextSteps: []string{"EDR·호스트 원본 증거 확보", "배포 및 관리자 작업 이력 대조"}, References: refs})
	case "ssrf":
		hs = append(hs, Hypothesis{ID: "server_egress", Title: "서버 측 후속 요청 조사", Statement: "서버 측 요청 유도가 실제로 발생했다면 서버에서 나온 연결과 요청 대상의 기록을 조사할 수 있습니다.", Preconditions: []string{"취약 요청과 서버 식별자 확인", "서버 출발 연결 자료 확보"}, RequiredLogs: []string{"서버 DNS·프록시·네트워크 송신 로그", "요청 대상 서비스 접근 로그"}, RequiredFields: []string{"출발 호스트", "목적지", "시각", "요청 ID 또는 프로세스"}, Hunt: "입력 요청과 서버 송신 이벤트를 요청 ID·프로세스·시간으로 대조합니다. 시간 근접만으로 인과관계를 확정하지 않습니다.", BenignAlternatives: []string{"정상 URL 미리보기·웹훅", "정기 서버 간 통신"}, NextSteps: []string{"송신 및 목적지 감사 로그 확보", "민감 대상의 실제 응답·접근 통제 확인"}, References: refs})
	default:
		hs = append(hs, Hypothesis{ID: "impact_review", Title: "취약점 영향과 후속 행동 수동 조사", Statement: "현재 분류에서 후속 공격을 단정할 수 없습니다. 취약점 성립 조건과 영향을 확인한 뒤 필요한 로그를 선택합니다.", Preconditions: []string{"취약점의 실제 성립 조건과 당시 자산 상태 확인"}, RequiredLogs: []string{"애플리케이션 감사 로그", "영향에 맞는 인증 또는 호스트 로그"}, RequiredFields: []string{"자산", "시각", "요청·세션·계정 식별자"}, Hunt: "관측 요청과 실제 영향의 연결을 확인할 자료를 확보합니다.", BenignAlternatives: []string{"정상 기능 사용", "승인된 테스트"}, NextSteps: []string{"취약점 영향 범위 확인", "필요 로그와 필드 구체화"}, References: refs})
	}
	facts, assumptions, warnings := defenseGuidance(family, defense)
	method := "근거 기반 조건부 조사 템플릿"
	if defense.RetestID > 0 || defense.ScenarioState != "" || defense.ExecutionID != "" {
		method = "취약점·방어검증 근거 기반 조건부 조사 안내"
	}
	limitations := []string{
		"이 안내의 가설은 과거 침해 판정이 아닙니다. 당시 취약 상태와 원본 로그를 별도로 확인해야 합니다.",
		"현재 자동 분석은 경로 접근과 제한적인 다중 경로 요청 흐름만 평가합니다. 나머지 가설은 필요한 원본 증거를 확인해야 합니다.",
	}
	if family == "error_information_exposure" {
		limitations = append(limitations, "응답 헤더·본문 또는 보존된 트래픽이 없다면 과거 오류 페이지·배너 노출 여부를 HTTP 상태 코드만으로 확인할 수 없습니다.")
	}
	return Plan{
		EngineVersion:       EngineVersion,
		Method:              method,
		Family:              family,
		Summary:             "확인된 재검증 사실, AI 시나리오 가정과 과거 로그 조사 가설을 구분합니다. 과거 침해는 별도 증거가 있어야 판단합니다.",
		VerifiedFacts:       facts,
		ScenarioAssumptions: assumptions,
		ContextWarnings:     warnings,
		Hypotheses:          hs,
		Limitations:         limitations,
	}
}

func errorDisclosure(text string) bool {
	errorSignal := containsAny(text, "error page", "error message", "stack trace", "traceback", "exception", "오류 페이지", "에러 페이지", "기본 오류 페이지", "서버 배너", "server banner", "관리자 연락처")
	exposureSignal := containsAny(text, "information disclosure", "information exposure", "정보 노출", "정보노출", "내부 정보", "server banner", "server header", "서버 배너", "배너 노출", "관리자 연락처", "root@localhost", "stack trace", "traceback")
	malformedExposure := containsAny(text, "malformed json", "비정상 json", "json 파서", "json parse") && containsAny(text, "500", "5xx") && exposureSignal
	return errorSignal && exposureSignal || malformedExposure
}

func informationExposure(text string) bool {
	return containsAny(text, "information", "disclosure", "exposure", "정보 노출", "정보노출", "노출", "directory", "listing", "디렉터리", "리스팅", "/ftp")
}

// The DB extracts a candidate only when one path is unambiguous. Validate it
// again before including it in user-facing guidance.
func safePlanPath(path string) string {
	if len(path) < 2 || len(path) > 160 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.Contains(path, "..") {
		return ""
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '_' || c == '-' || c == '.' || c == '~' {
			continue
		}
		return ""
	}
	return path
}

func defenseGuidance(family string, d DefenseGuidanceContext) ([]GuidanceFact, []GuidanceFact, []string) {
	facts := []GuidanceFact{}
	assumptions := []GuidanceFact{}
	warnings := []string{}
	if d.RetestID > 0 {
		source := fmt.Sprintf("ARTEX 재검증 #%d · 당시 기록", d.RetestID)
		switch {
		case d.RetestStatus == "completed" && d.RetestVerdict == "reproduced":
			statement := "ARTEX 재검증에서 취약점 재현으로 기록됐습니다."
			if family == "error_information_exposure" {
				observed := strings.ToLower(boundedEvidence(d.RetestSummary) + " " + boundedEvidence(d.RetestEvidence))
				details := []string{}
				if containsAny(observed, "malformed json", "비정상 json", "잘못된 json", "json 파서", "json parse") {
					details = append(details, "비정상 JSON 요청")
				}
				if containsAny(observed, "500", "internal server error") {
					details = append(details, "HTTP 500 응답")
				}
				if strings.Contains(observed, "apache") {
					details = append(details, "Apache 배너 또는 오류 페이지")
				}
				if containsAny(observed, "root@localhost", "관리자 연락처") {
					details = append(details, "관리자 연락처 노출")
				}
				if len(details) > 0 {
					statement = "ARTEX 재검증에서 " + strings.Join(details, ", ") + "이 기록됐습니다."
				}
			}
			facts = append(facts, GuidanceFact{Text: statement, Source: source})
		case d.RetestStatus == "completed" && d.RetestVerdict == "fixed":
			facts = append(facts, GuidanceFact{Text: "ARTEX 재검증 당시 원래 취약 조건이 재현되지 않았다고 기록됐습니다.", Source: source})
		case d.RetestStatus == "completed" && d.RetestVerdict == "inconclusive":
			warnings = append(warnings, "최근 ARTEX 재검증은 확인 불가로 끝났습니다. 원 진단만으로 당시 또는 현재 취약 상태를 확정하지 마세요.")
		default:
			warnings = append(warnings, "ARTEX 재검증이 완료되지 않았습니다. 현재 취약 상태는 재검증 결과로 확인되지 않았습니다.")
		}
	}
	if d.ExecutionState == "stale" {
		warnings = append(warnings, "방어검증 실행은 현재 설정·근거와 다릅니다. 위 재검증 사실은 당시 실행 기록이며 현재 취약 상태나 탐지 상태를 뜻하지 않습니다.")
	} else if d.ExecutionState == "current" && d.ExecutionID != "" {
		if conclusion := defenseOutcome(d.ExecutionDetection, d.ExecutionPrevention); conclusion != "" {
			facts = append(facts, GuidanceFact{Text: "방어검증 실행의 로그 근거 판정: " + conclusion + ". 이는 과거 침해 여부의 증거가 아닙니다.", Source: "방어검증 실행 #" + d.ExecutionID})
		}
	}
	if d.ScenarioState == "stale" {
		warnings = append(warnings, "AI 방어 시나리오는 이전 기준의 초안이므로 조사 가설에 반영하지 않았습니다.")
	} else if d.ScenarioState == "current" {
		for _, title := range d.ScenarioStageTitles {
			title = boundedGuidanceTitle(title)
			if title == "" {
				continue
			}
			assumptions = append(assumptions, GuidanceFact{Text: title, Source: "AI 방어 시나리오 초안 · 사실 미확인"})
			if len(assumptions) == 5 {
				break
			}
		}
	}
	return facts, assumptions, warnings
}

func defenseOutcome(detection, prevention string) string {
	parts := []string{}
	switch detection {
	case "detected":
		parts = append(parts, "탐지 확인")
	case "missed":
		parts = append(parts, "미탐지")
	}
	switch prevention {
	case "blocked":
		parts = append(parts, "차단 확인")
	case "not_blocked":
		parts = append(parts, "차단되지 않음")
	}
	return strings.Join(parts, " · ")
}

func boundedGuidanceTitle(title string) string {
	title = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, title))
	runes := []rune(title)
	if len(runes) > 160 {
		title = string(runes[:160])
	}
	return title
}

func boundedEvidence(value string) string {
	if len(value) > 8192 {
		return value[:8192]
	}
	return value
}
func containsAny(s string, values ...string) bool {
	for _, v := range values {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
