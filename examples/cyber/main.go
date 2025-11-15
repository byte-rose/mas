package main

import (
	"context"
	"fmt"
	"os"

	"github.com/voocel/mas/agent"
	"github.com/voocel/mas/cyber"
	"github.com/voocel/mas/llm"
	"github.com/voocel/mas/runtime"
	"github.com/voocel/mas/schema"
)

func main() {
	apiKey := os.Getenv("OPENAI_API_KEY")
	baseURL := os.Getenv("OPENAI_API_BASE_URL")
	model := llm.NewOpenAIModel("gpt-4o-mini", apiKey, baseURL)

	reconAgent := cyber.NewNetworkReconAgent(model)
	staticAgent := cyber.NewDefensiveCodeAgent(model)

	fmt.Println("=== Network Recon Workflow ===")
	runReconWorkflow(reconAgent, "example.com")

	fmt.Println("\n=== Static Analysis Workflow ===")
	snippet := `import "crypto/md5"
func insecure(token string) string {
    return fmt.Sprintf("%x", md5.Sum([]byte(token)))
}`
	runStaticWorkflow(staticAgent, snippet)
}

func runReconWorkflow(agentInstance agent.Agent, domain string) {
	ctx := runtime.NewContext(context.Background(), "demo", "recon")
	defer ctx.Close()

	message := schema.Message{Role: schema.RoleUser, Content: domain}
	response, err := agentInstance.Execute(ctx, message)
	if err != nil {
		fmt.Println("scan error:", err)
		return
	}
	fmt.Println("Agent response:")
	fmt.Println(response.Content)

	workflow := cyber.NewNetworkScanWorkflow(nil)
	wfOutput, err := workflow.Execute(ctx, message)
	if err != nil {
		fmt.Println("workflow scan error:", err)
		return
	}
	fmt.Println("Workflow output:")
	fmt.Println(wfOutput.Content)
}

func runStaticWorkflow(agentInstance agent.Agent, code string) {
	ctx := runtime.NewContext(context.Background(), "demo", "static")
	defer ctx.Close()

	message := schema.Message{Role: schema.RoleUser, Content: code}
	response, err := agentInstance.Execute(ctx, message)
	if err != nil {
		fmt.Println("analysis error:", err)
		return
	}
	fmt.Println("Agent response:")
	fmt.Println(response.Content)

	workflow := cyber.NewStaticAuditWorkflow(nil)
	wfOutput, err := workflow.Execute(ctx, message)
	if err != nil {
		fmt.Println("workflow analysis error:", err)
		return
	}
	fmt.Println("Workflow output:")
	fmt.Println(wfOutput.Content)
}
