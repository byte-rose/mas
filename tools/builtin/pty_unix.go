//go:build !windows

package builtin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"

	"github.com/voocel/mas/runtime"
	"github.com/voocel/mas/schema"
)

// Execute runs the provided command inside a pseudo-terminal.
func (t *PtyTool) Execute(ctx runtime.Context, input json.RawMessage) (json.RawMessage, error) {
	var params PtyInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, schema.NewToolError(t.Name(), "parse_input", err)
	}

	if strings.TrimSpace(params.Command) == "" {
		return nil, schema.NewValidationError("command", params.Command, "command cannot be empty")
	}

	timeout := t.defaultTimeout
	if params.TimeoutSeconds > 0 {
		timeout = time.Duration(params.TimeoutSeconds) * time.Second
	}

	execCtx := context.Context(ctx)
	var cancel context.CancelFunc
	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(execCtx, params.Command, params.Args...)
	if params.WorkDir != "" {
		cmd.Dir = params.WorkDir
	}
	if len(params.Env) > 0 {
		cmd.Env = mergeEnv(params.Env)
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, schema.NewToolError(t.Name(), "start_pty", err)
	}
	defer func() { _ = ptmx.Close() }()

	t.applyWindowSize(ptmx, params)

	maxBuffer := t.resolveMaxBuffer(params.MaxBufferBytes)
	var (
		outputBuf bytes.Buffer
		truncated bool
	)

	readerErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := ptmx.Read(buf)
			if n > 0 {
				if outputBuf.Len() < maxBuffer {
					remaining := maxBuffer - outputBuf.Len()
					if n > remaining {
						outputBuf.Write(buf[:remaining])
						truncated = true
					} else {
						outputBuf.Write(buf[:n])
					}
				} else {
					truncated = true
				}
			}

			if readErr != nil {
				if errors.Is(readErr, io.EOF) || errors.Is(readErr, syscall.EIO) {
					readerErr <- nil
				} else {
					readerErr <- readErr
				}
				return
			}
		}
	}()

	inputErr := make(chan error, 1)
	go func() {
		inputErr <- t.writeInput(execCtx, ptmx, params)
	}()

	waitErrChan := make(chan error, 1)
	go func() {
		waitErrChan <- cmd.Wait()
	}()

	start := time.Now()
	waitErr := <-waitErrChan
	_ = ptmx.Close() // unblock reader
	readErr := <-readerErr
	writeErr := <-inputErr
	duration := time.Since(start)

	output := PtyOutput{
		Command:       params.Command,
		ExitCode:      exitCode(cmd.ProcessState),
		Output:        outputBuf.String(),
		Success:       waitErr == nil && !errors.Is(execCtx.Err(), context.DeadlineExceeded),
		TimedOut:      errors.Is(execCtx.Err(), context.DeadlineExceeded),
		Truncated:     truncated,
		DurationMS:    duration.Milliseconds(),
		BytesCaptured: outputBuf.Len(),
	}

	if output.ExitCode != 0 {
		output.Success = false
	}

	if waitErr != nil {
		output.Error = waitErr.Error()
	} else if readErr != nil {
		output.Error = fmt.Sprintf("failed to read PTY output: %v", readErr)
		output.Success = false
	} else if writeErr != nil {
		output.Error = fmt.Sprintf("failed to write PTY input: %v", writeErr)
		output.Success = false
	} else if output.TimedOut {
		output.Error = schema.ErrToolTimeout.Error()
	}

	result, err := json.Marshal(output)
	if err != nil {
		return nil, schema.NewToolError(t.Name(), "marshal_output", err)
	}

	return result, nil
}

func (t *PtyTool) writeInput(ctx context.Context, ptmx *os.File, params PtyInput) error {
	if params.Input != "" {
		if _, err := ptmx.WriteString(params.Input); err != nil {
			return err
		}
	}

	for _, chunk := range params.InputSequence {
		if chunk.DelayMS > 0 {
			select {
			case <-time.After(time.Duration(chunk.DelayMS) * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		payload := chunk.Data
		if chunk.SendEnter {
			payload += "\n"
		}

		if payload == "" {
			continue
		}

		if _, err := io.WriteString(ptmx, payload); err != nil {
			return err
		}
	}

	return nil
}

func (t *PtyTool) applyWindowSize(ptmx *os.File, params PtyInput) {
	cols := t.defaultCols
	rows := t.defaultRows

	if params.Width > 0 {
		cols = uint16(params.Width)
	}
	if params.Height > 0 {
		rows = uint16(params.Height)
	}

	if cols == 0 || rows == 0 {
		return
	}

	_ = pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows})
}

func (t *PtyTool) resolveMaxBuffer(requested int) int {
	maxBuffer := t.maxBufferBytes
	if maxBuffer <= 0 {
		maxBuffer = defaultPTYBufferSize
	}

	if requested > 0 {
		if requested > maxPTYBufferSize {
			maxBuffer = maxPTYBufferSize
		} else {
			maxBuffer = requested
		}
	}

	return maxBuffer
}

func exitCode(state *os.ProcessState) int {
	if state == nil {
		return -1
	}
	return state.ExitCode()
}

func mergeEnv(custom map[string]string) []string {
	env := os.Environ()
	envMap := make(map[string]string, len(env)+len(custom))

	for _, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	for key, value := range custom {
		envMap[key] = value
	}

	result := make([]string, 0, len(envMap))
	for key, value := range envMap {
		result = append(result, fmt.Sprintf("%s=%s", key, value))
	}

	return result
}
