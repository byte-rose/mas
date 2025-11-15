package cyber

import (
	"github.com/voocel/mas/agent"
	"github.com/voocel/mas/llm"
	"github.com/voocel/mas/tools"
	cybertools "github.com/voocel/mas/tools/cyber"
)

// NewNetworkReconAgent creates an agent specialized in network reconnaissance.
func NewNetworkReconAgent(model llm.ChatModel, extra ...agent.Option) *agent.BaseAgent {
	scanner := cybertools.NewNetworkScannerTool(nil)

	opts := []agent.Option{
		agent.WithSystemPrompt("You are Recon, a cybersecurity agent focused on mapping exposed surfaces. Use the network_scanner tool to profile domains, summarize risky ports, and recommend hardening steps."),
		agent.WithTools(scanner),
		agent.WithCapabilities(&agent.AgentCapabilities{
			CoreCapabilities: []agent.Capability{
				agent.CapabilityToolUse,
				agent.CapabilityResearch,
				agent.CapabilityAnalysis,
			},
			Expertise:        []string{"network security", "surface mapping", "exposure analysis"},
			ToolTypes:        []string{scanner.Name()},
			Description:      "Performs scoped reconnaissance and highlights common exposures.",
			ComplexityLevel:  6,
			ConcurrencyLevel: 2,
		}),
	}

	opts = append(opts, extra...)
	return agent.NewAgent("network_recon", "Network Recon", model, opts...)
}

// NewDefensiveCodeAgent creates an agent that reviews code for vulnerabilities.
func NewDefensiveCodeAgent(model llm.ChatModel, extra ...agent.Option) *agent.BaseAgent {
	analyzer := cybertools.NewStaticAnalysisTool()

	opts := []agent.Option{
		agent.WithSystemPrompt("You are Sentinel, a secure-code reviewer. Analyze supplied code using the static_analysis tool and respond with weaknesses plus concrete remediations."),
		agent.WithTools(analyzer),
		agent.WithCapabilities(&agent.AgentCapabilities{
			CoreCapabilities: []agent.Capability{
				agent.CapabilityToolUse,
				agent.CapabilityAnalysis,
				agent.CapabilityEngineering,
			},
			Expertise:        []string{"secure coding", "static analysis", "threat modeling"},
			ToolTypes:        []string{analyzer.Name()},
			Description:      "Audits source code snippets and proposes defensive fixes.",
			ComplexityLevel:  7,
			ConcurrencyLevel: 1,
		}),
	}

	opts = append(opts, extra...)
	return agent.NewAgent("defensive_code", "Defensive Code Analyst", model, opts...)
}

// WithTools helper for building agent options outside constructors.
func WithCyberTools(toolList ...tools.Tool) agent.Option {
	return func(cfg *agent.AgentConfig) {
		cfg.Tools = append(cfg.Tools, toolList...)
	}
}
