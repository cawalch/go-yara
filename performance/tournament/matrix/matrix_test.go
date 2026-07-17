package matrix_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/performance/tournament/matrix"
	"github.com/cawalch/go-yara/performance/tournament/report"
)

func TestMatrixIsCompleteAndCompiles(t *testing.T) {
	rules := matrix.Rules()
	if len(rules) < 15 {
		t.Fatalf("rule cases = %d, want at least 15", len(rules))
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if _, exists := seen[rule.Name]; exists {
			t.Errorf("duplicate rule case %q", rule.Name)
		}
		seen[rule.Name] = struct{}{}
		if _, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), rule.Source); err != nil {
			t.Errorf("compile %s: %v", rule.Name, err)
		}
	}
	for _, required := range []string{
		"literal_single",
		"literal_set",
		"regex_literal_alternation",
		"regex_leading_class",
		"regex_no_atom",
		"regex_mixed_atoms",
		"string_count",
		"set_quantifier",
		"regex_set_16",
		"private_shared_8",
		"combined_skimmer_regex",
		"combined_skimmer_literals",
	} {
		if _, exists := seen[required]; !exists {
			t.Errorf("missing required rule case %q", required)
		}
	}
}

func TestDataAxesAreDeterministicAndExactSize(t *testing.T) {
	if len(matrix.Contents) != 4 {
		t.Fatalf("content cases = %d, want 4", len(matrix.Contents))
	}
	if len(matrix.Sizes) != 3 {
		t.Fatalf("sizes = %d, want 3", len(matrix.Sizes))
	}
	for _, content := range matrix.Contents {
		for _, size := range matrix.Sizes {
			first := matrix.Data(content, size)
			second := matrix.Data(content, size)
			if len(first) != size {
				t.Errorf("%s size = %d, want %d", content.Name, len(first), size)
			}
			if !bytes.Equal(first, second) {
				t.Errorf("%s/%d is not deterministic", content.Name, size)
			}
			if content.DenseMatches && !bytes.Contains(first, []byte("sendBeacon")) {
				t.Errorf("%s/%d is missing the match corpus", content.Name, size)
			}
			if !content.DenseMatches && bytes.Contains(first, []byte("cardnumber")) {
				t.Errorf("%s/%d unexpectedly contains a match token", content.Name, size)
			}
		}
	}
}

func TestBaselineCoversEveryMatrixCell(t *testing.T) {
	file, err := os.Open("../baseline.csv")
	if err != nil {
		t.Fatal(err)
	}
	baseline, readErr := report.ReadBaseline(file)
	closeErr := file.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	wantCells := len(matrix.Rules()) * len(matrix.Contents) * len(matrix.Sizes)
	if len(baseline) != wantCells {
		t.Fatalf("baseline cells = %d, want %d", len(baseline), wantCells)
	}
	for _, rule := range matrix.Rules() {
		for _, content := range matrix.Contents {
			for _, size := range matrix.Sizes {
				cell := fmt.Sprintf("%s/%s/%dKiB", rule.Name, content.Name, size>>10)
				if _, exists := baseline[cell]; !exists {
					t.Errorf("baseline is missing %s", cell)
				}
			}
		}
	}
}

func TestMatchFingerprintIsOrderIndependent(t *testing.T) {
	first := matrix.MatchFingerprint([]string{"bravo", "alpha"})
	second := matrix.MatchFingerprint([]string{"alpha", "bravo"})
	if first == 0 || first != second {
		t.Fatalf("fingerprints = %d and %d, want the same non-zero value", first, second)
	}
	if matrix.MatchFingerprint(nil) != 0 {
		t.Fatal("empty match fingerprint is not zero")
	}
}
