//go:build windows

package builtin

import (
	"encoding/json"
	"fmt"

	"github.com/voocel/mas/runtime"
	"github.com/voocel/mas/schema"
)

// Execute returns an explicit error on Windows hosts where PTY support is unavailable.
func (t *PtyTool) Execute(ctx runtime.Context, input json.RawMessage) (json.RawMessage, error) {
	return nil, schema.NewToolError("pty", "unsupported", fmt.Errorf("pty tool is not supported on Windows"))
}
