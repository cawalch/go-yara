package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestLibyaraEntrypointDefinednessAndResetDifferential(t *testing.T) {
	bin := libyaraOracle(t)

	src := `
rule ep_zero { condition: entrypoint == 0 }
rule ep_defined { condition: defined(entrypoint) }
rule ep_at { strings: $a = "MZ" condition: $a at entrypoint }
rule ep_eq_220 { condition: entrypoint == 0x220 }
`
	prog, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), src)
	if err != nil {
		t.Fatalf("CompileSourceWithContext() error = %v", err)
	}
	scanner := prog.NewScanner()
	defer scanner.Close()

	plain := []byte("MZ plain text file, not a PE")
	peData := pefixture.New(false)
	peData[0x220] = 'M'
	peData[0x221] = 'Z'

	yarPath := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(yarPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	// Scan PE first, then non-PE on the same Scanner to guard against entry point leaks.
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "pe", data: peData},
		{name: "non_pe_after_pe", data: plain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataPath := filepath.Join(t.TempDir(), "input.bin")
			if err := os.WriteFile(dataPath, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(bin, "--no-warnings", yarPath, dataPath).CombinedOutput()
			if err != nil {
				t.Fatalf("yara failed: %v (%s)", err, string(out))
			}
			var want []string
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if line == "" {
					continue
				}
				fields := strings.Fields(line)
				want = append(want, fields[0])
			}
			slices.Sort(want)

			res, err := scanner.Scan(tc.data)
			if err != nil {
				t.Fatalf("scanner.Scan() error = %v", err)
			}
			var got []string
			for _, m := range res.MatchedRules {
				got = append(got, m.Rule)
			}
			slices.Sort(got)

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("matched rules = %v, libyara = %v", got, want)
			}
		})
	}
}
