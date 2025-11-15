package compiler

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestInterpreterDebugMode(t *testing.T) {
	tests := []struct {
		name         string
		enableDebug  bool
		expectOutput bool
	}{
		{
			name:         "debug_mode_disabled",
			enableDebug:  false,
			expectOutput: false,
		},
		{
			name:         "debug_mode_enabled",
			enableDebug:  true,
			expectOutput: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout to check debug output
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Create simple bytecode: push 42, pop
			bytecode := []byte{
				byte(OpPush8), 42,
				byte(OpPop),
				byte(OpHalt),
			}

			interpreter := NewInterpreter(bytecode)

			if tt.enableDebug {
				interpreter.EnableDebugMode()
			}

			// Execute the bytecode
			err := interpreter.Execute()
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			// Restore stdout and capture output
			_ = w.Close()
			os.Stdout = oldStdout
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()

			// Check debug mode state
			if interpreter.IsDebugModeEnabled() != tt.enableDebug {
				t.Errorf("IsDebugModeEnabled() = %v, want %v", interpreter.IsDebugModeEnabled(), tt.enableDebug)
			}

			// Check if debug output was produced
			hasDebugOutput := len(output) > 0
			if hasDebugOutput != tt.expectOutput {
				t.Errorf("Debug output = %v, want %v", hasDebugOutput, tt.expectOutput)
				if len(output) > 0 {
					t.Logf("Debug output: %s", output)
				}
			}
		})
	}
}

func TestInterpreterDebugModeToggle(t *testing.T) {
	interpreter := NewInterpreter([]byte{byte(OpHalt)})

	// Initially disabled
	if interpreter.IsDebugModeEnabled() {
		t.Error("Debug mode should be disabled initially")
	}

	// Enable debug mode
	interpreter.EnableDebugMode()
	if !interpreter.IsDebugModeEnabled() {
		t.Error("Debug mode should be enabled after EnableDebugMode()")
	}

	// Disable debug mode
	interpreter.DisableDebugMode()
	if interpreter.IsDebugModeEnabled() {
		t.Error("Debug mode should be disabled after DisableDebugMode()")
	}
}
