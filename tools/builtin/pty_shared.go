package builtin

import (
	"time"

	"github.com/voocel/mas/tools"
)

const (
	defaultPTYTimeout    = 2 * time.Minute
	defaultPTYCols       = 120
	defaultPTYRows       = 32
	defaultPTYBufferSize = 1024 * 1024 // 1MB
	maxPTYBufferSize     = 5 * 1024 * 1024
)

// PtyTool executes interactive commands inside a pseudo-terminal.
type PtyTool struct {
	*tools.BaseTool
	defaultTimeout time.Duration
	defaultCols    uint16
	defaultRows    uint16
	maxBufferBytes int
}

// PtyInputChunk represents scripted input fed into the PTY.
type PtyInputChunk struct {
	Data      string `json:"data" description:"Raw data to send to the PTY"`
	SendEnter bool   `json:"send_enter,omitempty" description:"Append a newline after data"`
	DelayMS   int    `json:"delay_ms,omitempty" description:"Delay before sending data in milliseconds"`
}

// PtyInput captures PTY execution parameters.
type PtyInput struct {
	Command        string            `json:"command" description:"Binary or script to execute"`
	Args           []string          `json:"args,omitempty" description:"Arguments passed to the command"`
	WorkDir        string            `json:"workdir,omitempty" description:"Working directory for the process"`
	Env            map[string]string `json:"env,omitempty" description:"Environment variables"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" description:"Overrides the default timeout"`
	Input          string            `json:"input,omitempty" description:"Raw input written once to the PTY"`
	InputSequence  []PtyInputChunk   `json:"input_sequence,omitempty" description:"Interactive inputs written sequentially"`
	Width          int               `json:"width,omitempty" description:"PTY width (columns)"`
	Height         int               `json:"height,omitempty" description:"PTY height (rows)"`
	MaxBufferBytes int               `json:"max_buffer_bytes,omitempty" description:"Maximum bytes captured from PTY output"`
}

// PtyOutput contains execution results returned to the agent.
type PtyOutput struct {
	Success       bool   `json:"success"`
	Command       string `json:"command"`
	ExitCode      int    `json:"exit_code"`
	Output        string `json:"output,omitempty"`
	Error         string `json:"error,omitempty"`
	TimedOut      bool   `json:"timed_out,omitempty"`
	Truncated     bool   `json:"truncated,omitempty"`
	DurationMS    int64  `json:"duration_ms"`
	BytesCaptured int    `json:"bytes_captured"`
}

// NewPtyTool constructs a PTY-enabled tool.
func NewPtyTool() *PtyTool {
	schema := tools.CreateToolSchema(
		"Execute interactive commands inside a pseudo-terminal and capture the resulting output.",
		map[string]interface{}{
			"command":          tools.StringProperty("Binary or script to execute"),
			"args":             tools.ArrayProperty("Command arguments", "string"),
			"workdir":          tools.StringProperty("Working directory"),
			"env":              tools.ObjectProperty("Environment variables", nil),
			"timeout_seconds":  tools.NumberProperty("Timeout in seconds before the PTY is terminated"),
			"input":            tools.StringProperty("Initial input written directly to the PTY"),
			"input_sequence":   tools.ArrayProperty("Ordered PTY inputs with optional delays", "object"),
			"width":            tools.NumberProperty("PTY column size"),
			"height":           tools.NumberProperty("PTY row size"),
			"max_buffer_bytes": tools.NumberProperty("Maximum bytes captured from the PTY stream"),
		},
		[]string{"command"},
	)

	return &PtyTool{
		BaseTool:       tools.NewBaseTool("pty", "Interactive PTY execution tool", schema),
		defaultTimeout: defaultPTYTimeout,
		defaultCols:    defaultPTYCols,
		defaultRows:    defaultPTYRows,
		maxBufferBytes: defaultPTYBufferSize,
	}
}
