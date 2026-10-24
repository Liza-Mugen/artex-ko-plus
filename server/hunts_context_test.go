package server

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/hunting"
)

func TestHuntStageContextPreservesCompleteShortContract(t *testing.T) {
	stage := hunting.Stage{ID: "stage-1", DetectionQuestion: "실제 요청이 기록됐는가?", RequiredFields: []string{"timestamp", "target", "path"}, SuccessCriteria: "원본의 대상과 요청을 확인합니다.", BenignAlternatives: []string{"정상 요청", "승인 점검"}}
	question, truncated, err := huntStageQuestion(stage, nil)
	var view huntStageContext
	if err != nil || truncated || len(question) > huntStageContextBytes || json.Unmarshal([]byte(question), &view) != nil {
		t.Fatalf("short contract lost: question=%q truncated=%v err=%v", question, truncated, err)
	}
	if view.DetectionQuestion != stage.DetectionQuestion || view.SuccessCriteria != stage.SuccessCriteria || !reflect.DeepEqual(view.RequiredFields, stage.RequiredFields) || !reflect.DeepEqual(view.BenignAlternatives, stage.BenignAlternatives) {
		t.Fatal("an affordable contract was changed")
	}
}

func TestHuntLongKoreanStageContractRemainsValidInsideInvestigatorClip(t *testing.T) {
	stage := hunting.Stage{ID: "stage-1", DetectionQuestion: strings.Repeat("원본에서 같은 요청과 후속 행동을 확인할 수 있는가?", 70), RequiredFields: []string{"timestamp", "target", "path", "process.parent_image", "process.command_line"}, SuccessCriteria: strings.Repeat("요청과 호스트 원본의 연결을 확인하며 상태 코드만으로 코드 실행을 확정하지 않습니다.", 60), BenignAlternatives: []string{strings.Repeat("승인된 관리자 작업과 정상 사용일 수 있습니다.", 40), "정기 상태 점검"}}
	prior := []hunting.Observation{{StageID: "earlier", Kind: "observed", Summary: strings.Repeat("선행 관측은 확인된 원문을 참조한 활동 해석입니다.", 50)}, {StageID: "later", Kind: "inferred", Summary: strings.Repeat("이전 추론은 확정 사실이 아닙니다.", 50)}}
	question, truncated, err := huntStageQuestion(stage, prior)
	var view huntStageContext
	if err != nil || !truncated || !utf8.ValidString(question) || len(question) > huntStageContextBytes || json.Unmarshal([]byte(question), &view) != nil {
		t.Fatalf("unsafe clipping: bytes=%d truncated=%v err=%v", len(question), truncated, err)
	}
	if !reflect.DeepEqual(view.RequiredFields, stage.RequiredFields) || !view.Truncated || view.DetectionQuestion == "" || view.SuccessCriteria == "" || len(view.BenignAlternatives) == 0 || !strings.Contains(view.Notice, "미확인") {
		t.Fatalf("requirements or explicit truncation notice missing: %+v", view)
	}
	if len(stage.DetectionQuestion) < huntStageContextBytes || len(stage.BenignAlternatives) != 2 || len(prior) != 2 {
		t.Fatal("original archived design or observations were mutated")
	}
}

func TestHuntStageContextNeverDropsSixteenMaximumLengthFields(t *testing.T) {
	fields := []string{}
	for i := 0; i < 16; i++ {
		fields = append(fields, fmt.Sprintf("field_%02d_%s", i, strings.Repeat("x", 91)))
	}
	stage := hunting.Stage{ID: "stage-1", DetectionQuestion: "활동 확인?", RequiredFields: fields, SuccessCriteria: "원문 확인", BenignAlternatives: []string{"정상 활동"}}
	question, _, err := huntStageQuestion(stage, nil)
	var view huntStageContext
	if err != nil || len(question) > huntStageContextBytes || json.Unmarshal([]byte(question), &view) != nil || !reflect.DeepEqual(view.RequiredFields, fields) {
		t.Fatalf("maximum fields were lost: bytes=%d err=%v view=%+v", len(question), err, view)
	}
	for _, field := range view.RequiredFields {
		if len(field) != 100 {
			t.Fatal("fixture does not cover the full supported field length")
		}
	}
}

func TestHuntStageContextFailsClosedWhenMinimumContractCannotFit(t *testing.T) {
	fields := []string{}
	for i := 0; i < 16; i++ {
		fields = append(fields, fmt.Sprintf("field_%02d_%s", i, strings.Repeat("x", 91)))
	}
	// JSON escaping is counted as part of the transmitted contract, not just
	// the source string length. Even minimum quoted excerpts cannot fit here.
	stage := hunting.Stage{ID: strings.Repeat("s", 64), DetectionQuestion: strings.Repeat(`"`, 1000), RequiredFields: fields, SuccessCriteria: strings.Repeat(`"`, 1000), BenignAlternatives: []string{strings.Repeat(`"`, 1000)}}
	question, truncated, err := huntStageQuestion(stage, nil)
	if err == nil || question != "" || !truncated {
		t.Fatal("a rejected contract was still returned for execution")
	}
}

func TestHuntStageSummaryCannotExceedProgressEventLimit(t *testing.T) {
	question := strings.Repeat("한", 2000)
	summary := huntStageSummary(question)
	if !utf8.ValidString(summary) || utf8.RuneCountInString(summary) > 901 || !strings.HasSuffix(summary, "…") || utf8.RuneCountInString(question) != 2000 {
		t.Fatal("valid long questions can still exceed event limits")
	}
}
