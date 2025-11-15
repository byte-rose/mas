package cyber

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/voocel/mas/runtime"
	"github.com/voocel/mas/schema"
	"github.com/voocel/mas/tools"
)

// StaticAnalysisTool performs lightweight secure-code reviews.
type StaticAnalysisTool struct {
	*tools.BaseTool
	detectors []issueDetector
}

// StaticAnalysisInput captures the analysis request.
type StaticAnalysisInput struct {
	Language string `json:"language,omitempty" description:"Language hint (go, python, javascript, etc)"`
	Code     string `json:"code" description:"Source snippet to inspect"`
	FileName string `json:"file_name,omitempty" description:"Optional filename for context"`
	Target   string `json:"target,omitempty" description:"Component or repository name"`
}

// IssueReport describes a single finding.
type IssueReport struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	Evidence       string `json:"evidence"`
}

// StaticAnalysisReport summarizes tool output.
type StaticAnalysisReport struct {
	Success         bool          `json:"success"`
	Language        string        `json:"language"`
	FileName        string        `json:"file_name,omitempty"`
	Target          string        `json:"target,omitempty"`
	IssueCount      int           `json:"issue_count"`
	Score           int           `json:"score"`
	Issues          []IssueReport `json:"issues,omitempty"`
	GeneratedAt     time.Time     `json:"generated_at"`
	Recommendations []string      `json:"recommendations,omitempty"`
}

type issueDetector struct {
	id             string
	severity       string
	description    string
	recommendation string
	languages      []string
	regex          *regexp.Regexp
}

// NewStaticAnalysisTool constructs the analyzer.
func NewStaticAnalysisTool() *StaticAnalysisTool {
	schema := tools.CreateToolSchema(
		"Perform static analysis on supplied code snippets to highlight risky constructs and offer mitigations.",
		map[string]interface{}{
			"language":  tools.StringProperty("Optional language hint (go, python, javascript, etc.)"),
			"code":      tools.StringProperty("Source code snippet to scan"),
			"file_name": tools.StringProperty("Optional filename for context"),
			"target":    tools.StringProperty("Repository or component label"),
		},
		[]string{"code"},
	)

	return &StaticAnalysisTool{
		BaseTool:  tools.NewBaseTool("static_analysis", "Static secure-code analysis", schema),
		detectors: defaultIssueDetectors(),
	}
}

// Execute runs the static checks.
func (t *StaticAnalysisTool) Execute(ctx runtime.Context, input json.RawMessage) (json.RawMessage, error) {
	var params StaticAnalysisInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, schema.NewToolError(t.Name(), "parse_input", err)
	}

	if strings.TrimSpace(params.Code) == "" {
		return nil, schema.NewValidationError("code", params.Code, "code snippet is required")
	}

	language := strings.ToLower(strings.TrimSpace(params.Language))
	if language == "" && params.FileName != "" {
		language = inferLanguageFromFile(params.FileName)
	}

	findings := t.detectIssues(language, params.Code)
	score := computeRiskScore(findings)

	recommendations := make([]string, 0, len(findings))
	for _, finding := range findings {
		recommendations = append(recommendations, finding.Recommendation)
	}

	report := StaticAnalysisReport{
		Success:         true,
		Language:        language,
		FileName:        params.FileName,
		Target:          params.Target,
		IssueCount:      len(findings),
		Score:           score,
		Issues:          findings,
		GeneratedAt:     time.Now().UTC(),
		Recommendations: uniqueStrings(recommendations),
	}

	payload, err := json.Marshal(report)
	if err != nil {
		return nil, schema.NewToolError(t.Name(), "marshal_output", err)
	}
	return payload, nil
}

func (t *StaticAnalysisTool) detectIssues(language, code string) []IssueReport {
	normalized := strings.ReplaceAll(code, "\r\n", "\n")
	findings := make([]IssueReport, 0)

	for _, detector := range t.detectors {
		if len(detector.languages) > 0 && language != "" && !containsString(detector.languages, language) {
			continue
		}

		loc := detector.regex.FindString(normalized)
		if loc == "" {
			continue
		}

		finding := IssueReport{
			ID:             detector.id,
			Severity:       detector.severity,
			Description:    detector.description,
			Recommendation: detector.recommendation,
			Evidence:       snippetSample(loc),
		}
		findings = append(findings, finding)
	}

	return findings
}

func defaultIssueDetectors() []issueDetector {
	build := func(id, severity, description, recommendation string, pattern string, languages ...string) issueDetector {
		return issueDetector{
			id:             id,
			severity:       severity,
			description:    description,
			recommendation: recommendation,
			languages:      languages,
			regex:          regexp.MustCompile(pattern),
		}
	}

	detectors := []issueDetector{
		build("crypto-weak-hash", "medium",
			"Usage of weak hash functions (MD5/SHA1) detected",
			"Use SHA-256 or stronger algorithms via crypto/sha256 or hashlib.sha256.",
			`(?i)md5\.New|md5\.Sum|sha1\.New|hashlib\.md5|hashlib\.sha1`, "go", "python", "javascript"),
		build("command-shell", "high",
			"Shell execution with user-controlled input may allow command injection",
			"Prefer exec.CommandContext with explicit arguments or subprocess without shell=True.",
			`(?i)exec\.Command\(.*\)|subprocess\.Popen\(.*shell=True|os\.system`, "go", "python"),
		build("eval-dynamic", "high",
			"Dynamic eval detected which can execute arbitrary code",
			"Avoid eval/Function constructors. Use safe parsers or sandboxes.",
			`(?i)\beval\(|new Function\(`, "javascript", "python"),
		build("insecure-http", "medium",
			"Insecure HTTP URL detected for sensitive operations",
			"Use HTTPS endpoints for authentication and data submission.",
			`http://[^\s'"]+`, "go", "python", "javascript"),
		build("hardcoded-secret", "medium",
			"Possible hard-coded secret or credential found",
			"Move secrets into environment variables or secret managers.",
			`(?i)(api_key|secret|password)\s*[:=]\s*["'][^"']+`, "go", "python", "javascript"),
		build("insecure-rand", "low",
			"Predictable random source detected",
			"Use crypto/rand or secrets module for security-sensitive randomness.",
			`math/rand|random\.random`, "go", "python"),
	}

	return detectors
}

func inferLanguageFromFile(fileName string) string {
	lower := strings.ToLower(fileName)
	switch {
	case strings.HasSuffix(lower, ".go"):
		return "go"
	case strings.HasSuffix(lower, ".py"):
		return "python"
	case strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".ts"), strings.HasSuffix(lower, ".jsx"):
		return "javascript"
	case strings.HasSuffix(lower, ".rs"):
		return "rust"
	case strings.HasSuffix(lower, ".java"):
		return "java"
	default:
		return ""
	}
}

func snippetSample(snippet string) string {
	const maxLen = 240
	if len(snippet) <= maxLen {
		return snippet
	}
	return snippet[:maxLen] + "..."
}

func computeRiskScore(issues []IssueReport) int {
	if len(issues) == 0 {
		return 0
	}

	score := 0
	for _, issue := range issues {
		switch strings.ToLower(issue.Severity) {
		case "critical":
			score += 5
		case "high":
			score += 4
		case "medium":
			score += 3
		case "low":
			score += 1
		default:
			score += 2
		}
	}
	return score
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if strings.EqualFold(item, target) {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
