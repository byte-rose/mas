//go:build !windows

package builtin

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/voocel/mas/runtime"
)

func TestPtyToolSimpleCommand(t *testing.T) {
	requirePTY(t)

	ctx := runtime.NewContext(context.Background(), "test-session", "trace")
	defer ctx.Close()

	tool := NewPtyTool()
	input := PtyInput{
		Command: "/bin/sh",
		Args:    []string{"-c", "printf foo"},
	}

	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}

	data, err := tool.Execute(ctx, payload)
	if err != nil {
		t.Fatalf("tool execute failed: %v", err)
	}

	var output PtyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	if !output.Success {
		t.Fatalf("expected success, got output: %+v", output)
	}

	if strings.TrimSpace(output.Output) != "foo" {
		t.Fatalf("expected output foo, got %q", output.Output)
	}
}

func TestPtyToolInteractiveInput(t *testing.T) {
	requirePTY(t)

	ctx := runtime.NewContext(context.Background(), "test-session", "trace")
	defer ctx.Close()

	tool := NewPtyTool()
	input := PtyInput{
		Command: "/bin/sh",
		Args:    []string{"-c", "read line; printf \"value:%s\" \"$line\""},
		InputSequence: []PtyInputChunk{
			{Data: "hello-world", SendEnter: true},
		},
		TimeoutSeconds: 5,
	}

	payload, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}

	data, err := tool.Execute(ctx, payload)
	if err != nil {
		t.Fatalf("tool execute failed: %v", err)
	}

	var output PtyOutput
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	if !output.Success {
		t.Fatalf("expected success, got output: %+v", output)
	}

	if !strings.Contains(output.Output, "value:hello-world") {
		t.Fatalf("output %q missing expected data", output.Output)
	}
}

func requirePTY(t *testing.T) {
	t.Helper()
	f, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("skipping PTY tests: %v", err)
		return
	}
	_ = f.Close()
}
