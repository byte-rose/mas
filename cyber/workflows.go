package cyber

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/voocel/mas/runtime"
	"github.com/voocel/mas/schema"
	cybertools "github.com/voocel/mas/tools/cyber"
	"github.com/voocel/mas/workflows"
)

// NetworkScanWorkflow orchestrates reconnaissance steps.
type NetworkScanWorkflow struct {
	*workflows.BaseWorkflow
	scanner *cybertools.NetworkScannerTool
}

// StaticAuditWorkflow orchestrates static analysis reviews.
type StaticAuditWorkflow struct {
	*workflows.BaseWorkflow
	analyzer *cybertools.StaticAnalysisTool
}

// NewNetworkScanWorkflow builds the recon workflow.
func NewNetworkScanWorkflow(scanner *cybertools.NetworkScannerTool) *NetworkScanWorkflow {
	if scanner == nil {
		scanner = cybertools.NewNetworkScannerTool(nil)
	}
	config := workflows.WorkflowConfig{
		Name:        "network_recon_workflow",
		Description: "Map exposed surfaces for supplied domains and highlight risky ports.",
		Type:        workflows.WorkflowTypeChain,
	}

	return &NetworkScanWorkflow{
		BaseWorkflow: workflows.NewBaseWorkflow(config),
		scanner:      scanner,
	}
}

// NewStaticAuditWorkflow builds the defensive workflow.
func NewStaticAuditWorkflow(analyzer *cybertools.StaticAnalysisTool) *StaticAuditWorkflow {
	if analyzer == nil {
		analyzer = cybertools.NewStaticAnalysisTool()
	}

	config := workflows.WorkflowConfig{
		Name:        "static_analysis_workflow",
		Description: "Inspect code snippets for insecure patterns and remediation advice.",
		Type:        workflows.WorkflowTypeChain,
	}

	return &StaticAuditWorkflow{
		BaseWorkflow: workflows.NewBaseWorkflow(config),
		analyzer:     analyzer,
	}
}

// Execute runs a recon scan, expecting the domain inside message content or metadata.
func (w *NetworkScanWorkflow) Execute(ctx runtime.Context, input schema.Message) (schema.Message, error) {
	domain := strings.TrimSpace(input.Content)
	if metaDomain, ok := input.GetMetadata("domain"); ok {
		if s, ok := metaDomain.(string); ok && s != "" {
			domain = s
		}
	}
	if domain == "" {
		return schema.Message{}, schema.NewValidationError("domain", domain, "workflow requires a domain in message content or metadata")
	}

	payload, err := json.Marshal(cybertools.NetworkScanInput{Domain: domain})
	if err != nil {
		return schema.Message{}, err
	}

	data, err := w.scanner.Execute(ctx, payload)
	if err != nil {
		return schema.Message{}, err
	}

	return schema.Message{
		Role:    schema.RoleAssistant,
		Content: string(data),
	}, nil
}

// ExecuteStream is not streaming for this workflow.
func (w *NetworkScanWorkflow) ExecuteStream(ctx runtime.Context, input schema.Message) (<-chan schema.StreamEvent, error) {
	return nil, schema.ErrModelNotSupported
}

// Execute runs static code analysis; message content should contain source code.
func (w *StaticAuditWorkflow) Execute(ctx runtime.Context, input schema.Message) (schema.Message, error) {
	if strings.TrimSpace(input.Content) == "" {
		return schema.Message{}, schema.NewValidationError("content", input.Content, "provide code within the message content")
	}

	fileName := ""
	if metaFile, ok := input.GetMetadata("file_name"); ok {
		fileName, _ = metaFile.(string)
	}
	language := ""
	if metaLang, ok := input.GetMetadata("language"); ok {
		language, _ = metaLang.(string)
	}

	payload, err := json.Marshal(cybertools.StaticAnalysisInput{
		Code:     input.Content,
		FileName: fileName,
		Language: language,
	})
	if err != nil {
		return schema.Message{}, err
	}

	data, err := w.analyzer.Execute(ctx, payload)
	if err != nil {
		return schema.Message{}, err
	}

	return schema.Message{
		Role:    schema.RoleAssistant,
		Content: string(data),
	}, nil
}

// ExecuteStream returns not supported for static audit workflow.
func (w *StaticAuditWorkflow) ExecuteStream(ctx runtime.Context, input schema.Message) (<-chan schema.StreamEvent, error) {
	return nil, schema.ErrModelNotSupported
}

// Validate extends the base validation with tool sanity checks.
func (w *NetworkScanWorkflow) Validate() error {
	if w.scanner == nil {
		return fmt.Errorf("network scanner tool not configured")
	}
	return w.BaseWorkflow.Validate()
}

// Validate extends the base validation with analyzer checks.
func (w *StaticAuditWorkflow) Validate() error {
	if w.analyzer == nil {
		return fmt.Errorf("static analysis tool not configured")
	}
	return w.BaseWorkflow.Validate()
}
