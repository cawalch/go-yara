package compiler

import (
	"slices"
	"sort"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func matchedRuleNamesForEntrypointTest(res *ScanResult) []string {
	var names []string
	for _, r := range res.MatchedRules {
		names = append(names, r.Rule)
	}
	sort.Strings(names)
	return names
}

func TestEntrypointUndefinedOnNonPEAndResetAcrossScans(t *testing.T) {
	program, err := NewCompiler().CompileSource(`
rule ep_zero { condition: entrypoint == 0 }
rule ep_defined { condition: defined(entrypoint) }
rule ep_at { strings: $a = "MZ" condition: $a at entrypoint }
rule ep_undef { condition: not defined(entrypoint) }
`)
	if err != nil {
		t.Fatalf("CompileSource() error = %v", err)
	}

	plain := []byte("MZ plain text file, not a PE")
	peData := pefixture.New(false)
	// Offset 0x220 is the mapped entry point of pefixture.New(false).
	peData[0x220] = 'M'
	peData[0x221] = 'Z'

	scanner := program.NewScanner()
	defer scanner.Close()

	// 1. Plain input before any PE scan: entrypoint is undefined.
	resPlain, err := scanner.Scan(plain)
	if err != nil {
		t.Fatalf("Scan(plain) error = %v", err)
	}
	if got := matchedRuleNamesForEntrypointTest(resPlain); !slices.Equal(got, []string{"ep_undef"}) {
		t.Fatalf("Scan(plain) matched = %v, want [ep_undef]", got)
	}

	// 2. Valid PE without "import pe": entrypoint is defined at 0x220.
	resPE, err := scanner.Scan(peData)
	if err != nil {
		t.Fatalf("Scan(pe) error = %v", err)
	}
	if got := matchedRuleNamesForEntrypointTest(resPE); !slices.Equal(got, []string{"ep_at", "ep_defined"}) {
		t.Fatalf("Scan(pe) matched = %v, want [ep_at ep_defined]", got)
	}

	// 3. Reuse the same Scanner on plain input: PE entrypoint must NOT leak.
	resAfter, err := scanner.Scan(plain)
	if err != nil {
		t.Fatalf("Scan(plain after PE) error = %v", err)
	}
	if got := matchedRuleNamesForEntrypointTest(resAfter); !slices.Equal(got, []string{"ep_undef"}) {
		t.Fatalf("Scan(plain after PE) matched = %v, want [ep_undef]", got)
	}

	// 4. Pooled CompiledProgram.Scan PE -> plain must also reset cleanly.
	for _, want := range []struct {
		data  []byte
		rules []string
	}{
		{peData, []string{"ep_at", "ep_defined"}},
		{plain, []string{"ep_undef"}},
	} {
		res, scanErr := program.Scan(want.data)
		if scanErr != nil {
			t.Fatalf("program.Scan() error = %v", scanErr)
		}
		if got := matchedRuleNamesForEntrypointTest(res); !slices.Equal(got, want.rules) {
			t.Fatalf("program.Scan() matched = %v, want %v", got, want.rules)
		}
	}
}
