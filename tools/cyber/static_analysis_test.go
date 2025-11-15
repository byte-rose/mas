package cyber

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/voocel/mas/runtime"
)

func TestStaticAnalysisToolDetectsEval(t *testing.T) {
	tool := NewStaticAnalysisTool()
	input := StaticAnalysisInput{
		Language: "javascript",
		Code:     `function run(u){ return eval(u); }`,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}

	ctx := runtime.NewContext(context.Background(), "test", "trace")
	defer ctx.Close()

	resultRaw, err := tool.Execute(ctx, payload)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	var report StaticAnalysisReport
	if err := json.Unmarshal(resultRaw, &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if report.IssueCount == 0 {
		t.Fatalf("expected findings for eval usage")
	}
}

func TestStaticAnalysisInfersLanguageFromFileName(t *testing.T) {
	tool := NewStaticAnalysisTool()
	input := StaticAnalysisInput{
		FileName: "crypto.go",
		Code: `import "crypto/md5"
func hash(data []byte) string {
    sum := md5.Sum(data)
    return fmt.Sprintf("%x", sum)
}`,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}

	ctx := runtime.NewContext(context.Background(), "test", "trace")
	defer ctx.Close()

	resultRaw, err := tool.Execute(ctx, payload)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	var report StaticAnalysisReport
	if err := json.Unmarshal(resultRaw, &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if report.Language != "go" {
		t.Fatalf("expected language go, got %s", report.Language)
	}
	if report.IssueCount == 0 {
		t.Fatalf("expected weak hash detection")
	}
}
