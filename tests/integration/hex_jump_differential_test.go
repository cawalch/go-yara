package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraHexJumpDifferential(t *testing.T) {
	bin := libyaraOracle(t)

	compileCases := []struct {
		name string
		hex  string
		want bool
	}{
		{"valid_max_int32", "{ 41 [0-2147483647] 43 }", true},
		{"valid_unbounded_max_int32", "{ 41 [2147483647-] 43 }", true},
		{"valid_zero_zero", "{ 41 [0-0] 43 }", true},
		{"invalid_above_int32", "{ 41 [0-2147483648] 43 }", false},
		{"invalid_single_above_int32", "{ 41 [2147483648] 43 }", false},
		{"invalid_uint32_overflow", "{ 41 [4294967296] 43 }", false},
		{"invalid_reversed", "{ 41 [10-9] 43 }", false},
	}

	emptyBuf := []byte{}
	noMatchBuf := bytes.Repeat([]byte{'A'}, 16384)
	matchBuf := append(bytes.Repeat([]byte{'A'}, 128), 'C')

	for _, tc := range compileCases {
		t.Run(tc.name, func(t *testing.T) {
			src := fmt.Sprintf("rule h { strings: $a = %s condition: $a }\n", tc.hex)
			yaraOK := runLibyaraCompileAndMatch(t, bin, src, emptyBuf)
			prog, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), src)
			goOK := err == nil
			if goOK != tc.want || yaraOK != tc.want {
				t.Fatalf("compile parity mismatch for %s: got=%v libyara=%v want=%v (err=%v)", tc.hex, goOK, yaraOK, tc.want, err)
			}
			if !goOK {
				return
			}
			for name, buf := range map[string][]byte{"no_match_16k": noMatchBuf, "match_129": matchBuf} {
				wantMatch := runLibyaraMatch(t, bin, src, buf)
				res, scanErr := prog.Scan(buf)
				if scanErr != nil {
					t.Fatalf("Scan(%s) error = %v", name, scanErr)
				}
				gotMatch := len(res.MatchedRules) > 0
				if gotMatch != wantMatch {
					t.Fatalf("%s/%s: gotMatch=%v, libyara=%v", tc.name, name, gotMatch, wantMatch)
				}
			}
		})
	}
}

func FuzzLibyaraHexJumpDifferential(f *testing.F) {
	bin := libyaraOracle(f)
	f.Add(int64(0), int64(2147483647), []byte("AAAABAAAC"))
	f.Add(int64(10), int64(9), []byte("AB"))
	f.Add(int64(0), int64(2147483648), []byte("AB"))
	f.Add(int64(1), int64(50000), []byte(strings.Repeat("A", 4096)))

	f.Fuzz(func(t *testing.T, minVal, maxVal int64, data []byte) {
		var rangeSpec string
		if maxVal < 0 {
			rangeSpec = fmt.Sprintf("[%d-]", minVal)
		} else {
			rangeSpec = fmt.Sprintf("[%d-%d]", minVal, maxVal)
		}
		src := fmt.Sprintf("rule h { strings: $a = { 41 %s 43 } condition: $a }\n", rangeSpec)

		prog, goErr := compiler.NewCompiler().CompileSourceWithContext(context.Background(), src)
		tmpDir := t.TempDir()
		yarPath := filepath.Join(tmpDir, "rule.yar")
		dataPath := filepath.Join(tmpDir, "input.bin")
		if err := os.WriteFile(yarPath, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dataPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "--no-warnings", yarPath, dataPath)
		out, yaraErr := cmd.CombinedOutput()
		yaraCompiled := yaraErr == nil

		if (goErr == nil) != yaraCompiled {
			t.Fatalf("compile divergence for %s: goErr=%v yaraErr=%v (%s)", rangeSpec, goErr, yaraErr, strings.TrimSpace(string(out)))
		}
		if goErr != nil {
			return
		}
		res, scanErr := prog.Scan(data)
		if scanErr != nil {
			t.Fatalf("Scan() error = %v", scanErr)
		}
		gotMatch := len(res.MatchedRules) > 0
		wantMatch := strings.Contains(string(out), "h ")
		if gotMatch != wantMatch {
			t.Fatalf("match divergence for %s (len=%d): got=%v libyara=%v", rangeSpec, len(data), gotMatch, wantMatch)
		}
	})
}

//nolint:revive // argument-limit: test helper
func runLibyaraCompileAndMatch(t *testing.T, bin, src string, data []byte) bool {
	t.Helper()
	yarPath := filepath.Join(t.TempDir(), "rule.yar")
	dataPath := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(yarPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--no-warnings", yarPath, dataPath)
	return cmd.Run() == nil
}

//nolint:revive // argument-limit: test helper
func runLibyaraMatch(t *testing.T, bin, src string, data []byte) bool {
	t.Helper()
	yarPath := filepath.Join(t.TempDir(), "rule.yar")
	dataPath := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(yarPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--no-warnings", yarPath, dataPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("yara execution failed: %v (%s)", err, string(out))
	}
	return strings.TrimSpace(string(out)) != ""
}
