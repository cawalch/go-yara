//go:build !race

package compiler

import "testing"

// TestHighEPSZeroAllocationContracts enforces zero-allocation fast paths on
// warmed-up scanners for high-EPS Kafka-style mixed credential corpora.
func TestHighEPSZeroAllocationContracts(t *testing.T) {
	mixedProgram, err := NewCompiler().CompileSource(highEPSRuleSource("mixed", 1_000))
	if err != nil {
		t.Fatal(err)
	}
	mixedScanner := mixedProgram.NewScanner(WithFastScan())
	defer mixedScanner.Close()

	cleanEvent := highEPSJSONEvent(256, 1, "")
	matchEvent := highEPSJSONEvent(256, 1, " sig_00001=AB123456")

	// Warm up scanner pools/state before measuring.
	if _, err := mixedScanner.Matches(cleanEvent); err != nil {
		t.Fatal(err)
	}
	if _, err := mixedScanner.Matches(matchEvent); err != nil {
		t.Fatal(err)
	}

	assertZeroAllocs := func(name string, fn func()) {
		t.Helper()
		if allocs := testing.AllocsPerRun(25, fn); allocs != 0 {
			t.Fatalf("%s: allocations = %.1f, want 0", name, allocs)
		}
	}

	assertZeroAllocs("mixed_1k_matches_clean", func() {
		matched, scanErr := mixedScanner.Matches(cleanEvent)
		if scanErr != nil || matched {
			t.Fatalf("Matches(clean) = (%v, %v)", matched, scanErr)
		}
	})
	assertZeroAllocs("mixed_1k_matches_hit", func() {
		matched, scanErr := mixedScanner.Matches(matchEvent)
		if scanErr != nil || !matched {
			t.Fatalf("Matches(hit) = (%v, %v)", matched, scanErr)
		}
	})
	assertZeroAllocs("mixed_1k_matching_rules_clean", func() {
		rules, scanErr := mixedScanner.MatchingRules(cleanEvent)
		if scanErr != nil || len(rules) != 0 {
			t.Fatalf("MatchingRules(clean) = (%v, %v)", rules, scanErr)
		}
	})

	corpusProgram, err := NewCompiler().CompileSource(corpusAtomSource(128))
	if err != nil {
		t.Fatal(err)
	}
	corpusScanner := corpusProgram.NewScanner()
	defer corpusScanner.Close()
	cleanLog := []byte("level=info request completed status=200")
	if _, err := corpusScanner.Matches(cleanLog); err != nil {
		t.Fatal(err)
	}
	assertZeroAllocs("corpus_128_matches_clean", func() {
		matched, scanErr := corpusScanner.Matches(cleanLog)
		if scanErr != nil || matched {
			t.Fatalf("Matches(cleanLog) = (%v, %v)", matched, scanErr)
		}
	})

	fanoutProgram, err := NewCompiler().CompileSource(compactPrefilterRules)
	if err != nil {
		t.Fatal(err)
	}
	fanoutScanner := fanoutProgram.NewScanner()
	defer fanoutScanner.Close()
	fanoutReject := []byte("event value=1234 event")
	if _, err := fanoutScanner.Matches(fanoutReject); err != nil {
		t.Fatal(err)
	}
	assertZeroAllocs("fanout_compact_matches_reject", func() {
		matched, scanErr := fanoutScanner.Matches(fanoutReject)
		if scanErr != nil || matched {
			t.Fatalf("Matches(fanoutReject) = (%v, %v)", matched, scanErr)
		}
	})

	evProgram, err := NewCompiler().CompileSource(`
rule cred_capture {
    strings:
        $tok = /token=([A-Za-z0-9]+)/ capture(secret = 1)
    evidence:
        credential = (secret) within 0 of secret
    condition:
        $tok
}
`)
	if err != nil {
		t.Fatal(err)
	}
	evScanner := evProgram.NewScanner(WithEvidence(64), WithBorrowedEvidence(true))
	defer evScanner.Close()
	if _, err := evScanner.Matches(cleanLog); err != nil {
		t.Fatal(err)
	}
	assertZeroAllocs("borrowed_evidence_matches_clean", func() {
		matched, scanErr := evScanner.Matches(cleanLog)
		if scanErr != nil || matched {
			t.Fatalf("Matches(cleanLog) = (%v, %v)", matched, scanErr)
		}
	})
}
