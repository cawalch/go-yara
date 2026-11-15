package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
)

func TestLibyaraConstantFoldOverflowDifferential(t *testing.T) {
	bin := libyaraOracle(t)
	dataPath := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(dataPath, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name              string
		condition         string
		wantErr           bool
		wantMatch         bool
		allowOracleSignal bool
	}{
		{name: "add_overflow", condition: `9223372036854775807 + 1 == 0`, wantErr: true},
		{name: "mul_overflow", condition: `~9223372036854775807 * 9223372036854775807 == 0`, wantErr: true},
		{name: "div_min_overflow", condition: `(-(9223372036854775807) - 1) \ -1 == 0`, wantErr: true},
		{name: "sub_min_overflow", condition: `0 - (-(9223372036854775807) - 1) == 0`, wantErr: true},
		{name: "neg_shift_left", condition: `1 << -1 == 0`, wantErr: true},
		{name: "neg_shift_right", condition: `1 >> -1 == 0`, wantErr: true},
		{name: "div_folded_zero", condition: `1 \ (2 - 2) == 0`, wantErr: true},
		{name: "mod_min_defined_false", condition: `defined((-(9223372036854775807) - 1) % -1)`, wantMatch: false, allowOracleSignal: true},
		{name: "mod_min_zero_false", condition: `((-(9223372036854775807) - 1) % -1) == 0`, wantMatch: false, allowOracleSignal: true},
		{name: "unary_min_wraps", condition: `-( -(9223372036854775807) - 1 ) == (-(9223372036854775807) - 1)`, wantMatch: true},
		{name: "shl_64_zero", condition: `(1 << 64) == 0`, wantMatch: true},
		{name: "shr_64_zero", condition: `(-1 >> 64) == 0`, wantMatch: true},
		{name: "runtime_shl_64_zero", condition: `(1 << (filesize + 63)) == 0`, wantMatch: true},
		{name: "runtime_shr_neg_undef", condition: `not defined(1 >> (filesize - 2))`, wantMatch: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "rule r { condition: " + tc.condition + " }\n"
			yarPath := filepath.Join(t.TempDir(), "rule.yar")
			if err := os.WriteFile(yarPath, []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			out, oracleErr := exec.Command(bin, "--no-warnings", yarPath, dataPath).CombinedOutput()
			oracleSignaled := false
			if oracleErr != nil && tc.allowOracleSignal {
				var exitErr *exec.ExitError
				if errors.As(oracleErr, &exitErr) && !exitErr.Exited() {
					// libyara < 4.6.0 on x86_64 raises SIGFPE on constant-folded INT64_MIN % -1
					// (fixed upstream in VirusTotal/yara#2211). Still verify go-yara's behavior.
					oracleSignaled = true
					t.Logf("libyara crashed with signal (%v); skipping oracle comparison", oracleErr)
				}
			}
			if !oracleSignaled {
				oracleCompileFailed := oracleErr != nil
				if oracleCompileFailed != tc.wantErr {
					t.Fatalf("libyara compile err = %v (%s), wantErr = %v", oracleErr, string(out), tc.wantErr)
				}
			}

			prog, goErr := compiler.NewCompiler().CompileSourceWithContext(context.Background(), src)
			if (goErr != nil) != tc.wantErr {
				t.Fatalf("go-yara compile err = %v, wantErr = %v", goErr, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			res, scanErr := prog.Scan([]byte("a"))
			if scanErr != nil {
				t.Fatalf("Scan() error = %v", scanErr)
			}
			goMatched := len(res.MatchedRules) == 1
			if goMatched != tc.wantMatch {
				t.Fatalf("go=%v want=%v", goMatched, tc.wantMatch)
			}
			if !oracleSignaled {
				oracleMatched := strings.TrimSpace(string(out)) != ""
				if goMatched != oracleMatched {
					t.Fatalf("go=%v libyara=%v want=%v", goMatched, oracleMatched, tc.wantMatch)
				}
			}
		})
	}
}
