package compiler

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestCombinedRegexPriority(t *testing.T) {
	expressions := []string{`key=[a-z]{16,32}!`, `key=[a-z]{16,32}?!`, `key=(ab|a)[a-z]{16}!`, `key=(a|ab)[a-z]{16}!`, `key=[a-z]{16,32}a`, `key=[a-z]{16,32}?a`, `key=(a?|ab)[a-z]{16}`}
	for _, expression := range expressions {
		p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule r {strings:$a=/%s/ condition:#a>0}`, expression))
		pattern := p.Rules[0].RegexPatterns["$a"]
		instructions, ok := decodeCombinedRegex(pattern)
		if !ok {
			t.Fatal(expression, "decode")
		}
		b := combinedRegexBuilder{nfa: combinedRegexNFA{states: []combinedRegexState{{}}}, edges: make(map[combinedRegexEdge]int)}
		if !b.add(instructions, sharedAutomatonEntry{}, pattern.Flags&regex.FlagsGreedy != 0) {
			t.Fatal(expression, "build")
		}
		scratch := combinedRegexScratch{}
		for n := 0; n < 40; n++ {
			for _, prefix := range []string{"key=", "key=ab", "key=b"} {
				data := []byte(prefix + strings.Repeat("a", n) + "!")
				b.nfa.match(data, &scratch, nil)
				matched, _, end := regex.ExecMatchBatch(nil, pattern.Code, data, pattern.Flags, 0)
				if (scratch.ends[0] > 0) != matched || matched && scratch.ends[0] != end {
					t.Fatalf("%s %q got=%d want=%t/%d", expression, data, scratch.ends[0], matched, end)
				}
			}
		}
	}
}

func TestCombinedRegexPublic(t *testing.T) {
	p := mustCompileStreamingProgram(t, combinedNFASource(16, "!"))
	groups := 0
	for _, e := range p.sharedLookup {
		if e.combined != nil && e.combined.leader >= 0 {
			groups++
		}
	}
	if groups < 4 {
		t.Fatalf("only %d grouped entries", groups)
	}
	old := *p
	old.scannerPool = nil
	old.sharedLookup = append([]sharedAutomatonEntry(nil), p.sharedLookup...)
	for i := range old.sharedLookup {
		old.sharedLookup[i].combined = nil
	}
	for _, n := range []int{0, 15, 16, 17, 31, 32, 33, 64} {
		data := []byte("key=" + strings.Repeat("a", n) + "!key=" + strings.Repeat("b", 20) + "!")
		got, err := p.Scan(data)
		if err != nil {
			t.Fatal(err)
		}
		want, err := old.Scan(data)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("n=%d: got=%+v want=%+v", n, got, want)
		}
		scanner := p.NewScanner()
		streamed, err := scanner.ScanReader(bytes.NewReader(data))
		scanner.Close()
		reference := old.NewScanner()
		oldStream, oldErr := reference.ScanReader(bytes.NewReader(data))
		reference.Close()
		if err != nil || oldErr != nil || !reflect.DeepEqual(streamed.Matches, oldStream.Matches) {
			t.Fatalf("stream %d: %v got=%+v want=%+v", n, err, streamed.Matches, got.Matches)
		}
	}
}

func TestCombinedRegexEligibility(t *testing.T) {
	for _, expression := range []string{`key=a+`, `^key=a`, `key=a$`, `key=\b[a-z]{16}`, `key=.{1,8}`} {
		p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule r {strings:$a=/%s/ condition:#a>0}`, expression))
		if _, ok := decodeCombinedRegex(p.Rules[0].RegexPatterns["$a"]); ok {
			t.Fatalf("accepted %s", expression)
		}
	}
	for _, code := range [][]byte{nil, {regex.OpLiteral}, {regex.OpClass}, {regex.OpJump, 0, 0}, {regex.OpJump, 255, 255}, {regex.OpSplitA, 255, 127}, {regex.OpLiteral, 'a', regex.OpJump, 1, 0, regex.OpMatch}, {255}} {
		if _, ok := decodeCombinedRegex(RegexPattern{Code: code}); ok {
			t.Fatalf("accepted malformed %v", code)
		}
	}
	p := mustCompileStreamingProgram(t, `rule r {strings:$a=/key=([a-z]{16,32})/ capture(value=1) condition:$a}`)
	if _, ok := decodeCombinedRegex(p.Rules[0].RegexPatterns["$a"]); ok {
		t.Fatal("accepted captures")
	}
	for _, mod := range []string{"wide", "ascii wide", "fullword"} {
		source := strings.ReplaceAll(combinedNFASource(8, "!"), "/ condition:", "/ "+mod+" condition:")
		p := mustCompileStreamingProgram(t, source)
		for _, entry := range p.sharedLookup {
			if entry.combined != nil {
				t.Fatal("grouped unsupported modifier", mod)
			}
		}
	}
}

func TestCombinedRegexCaps(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule r {strings:$a=/key=[a-z]{16,32}!/ condition:$a}`)
	instructions, ok := decodeCombinedRegex(p.Rules[0].RegexPatterns["$a"])
	if !ok {
		t.Fatal("decode")
	}
	for _, tc := range []struct {
		name string
		edit func(*combinedRegexBuilder)
	}{
		{"work", func(b *combinedRegexBuilder) { b.work = maxCombinedRegexWork }},
		{"accepts", func(b *combinedRegexBuilder) { b.accepts = maxCombinedRegexWork }},
		{"depth", func(b *combinedRegexBuilder) { b.nfa.states[0].depth = maxCombinedRegexDepth }},
		{"states", func(b *combinedRegexBuilder) { b.nfa.states = make([]combinedRegexState, maxCombinedRegexStates) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := combinedRegexBuilder{nfa: combinedRegexNFA{states: []combinedRegexState{{}}}, edges: make(map[combinedRegexEdge]int)}
			tc.edit(&b)
			if b.add(instructions, sharedAutomatonEntry{}, true) {
				t.Fatal("ignored cap")
			}
		})
	}
	// A difficult member must not leave a partially installed group.
	source := combinedNFASource(8, "!") + `rule huge {strings:$a=/key=\w{513}!/ condition:$a}`
	p = mustCompileStreamingProgram(t, source)
	for _, entry := range p.sharedLookup {
		if entry.combined != nil {
			t.Fatal("installed incomplete group")
		}
	}
}

func withoutCombinedRegex(p *CompiledProgram) *CompiledProgram {
	old := *p
	old.scannerPool = nil
	old.sharedLookup = append([]sharedAutomatonEntry(nil), p.sharedLookup...)
	for i := range old.sharedLookup {
		old.sharedLookup[i].combined = nil
	}
	return &old
}

func TestCombinedRegexReloadReuseAndLimits(t *testing.T) {
	source := combinedNFASource(16, "!") + `
rule conjunction {strings:$a=/key=[a-z0-9]{16,32}!/ $b=/key=[a-z0-9]{16,33}!/ condition:$a and $b}
rule gated {strings:$gate="required" $a=/key=[a-z0-9]{16,34}!/ condition:all of them}
rule forbidden {strings:$gate="forbidden" $a=/key=[a-z0-9]{16,35}!/ condition:$a and not $gate}`
	p := mustCompileStreamingProgram(t, source)
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*CompiledProgram{p, restored} {
		grouped := false
		for _, entry := range p.sharedLookup {
			grouped = grouped || entry.combined != nil
		}
		if !grouped {
			t.Fatal("missing group")
		}
		reference := withoutCombinedRegex(p)
		for _, opts := range [][]ScannerOption{{}, {WithFastScan()}, {WithMaxMatchSpan(24)}, {WithMaxMatchSpan(40)}, {WithMatchData(128)}} {
			s, old := p.NewScanner(opts...), reference.NewScanner(opts...)
			for _, data := range [][]byte{[]byte("key=" + strings.Repeat("a", 20) + "! key=" + strings.Repeat("b", 32) + "!"), nil, []byte("required forbidden key=" + strings.Repeat("a", 24) + "!")} {
				got, err := s.Scan(data)
				if err != nil {
					t.Fatal(err)
				}
				want, err := old.Scan(data)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("scan mismatch: %v", err)
				}
				saved := fmt.Sprintf("%#v", got.Matches)
				if _, err := s.Scan(nil); err != nil {
					t.Fatal(err)
				}
				if fmt.Sprintf("%#v", got.Matches) != saved {
					t.Fatal("result ownership changed")
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := s.ScanWithContext(ctx, []byte("key="+strings.Repeat("a", 20)+"!")); err == nil {
				t.Fatal("cancellation ignored")
			}
			s.Close()
			old.Close()
		}
	}
}

func FuzzCombinedRegex(f *testing.F) {
	expressions := []string{`key=[a-z]{16,32}!`, `key=[a-z]{16,32}?!`, `key=[a-z]{16,32}a`, `key=[a-z]{16,32}?a`, `key=(ab|a)[a-z]{1,24}`, `key=(a|ab)[a-z]{1,24}`, `key=(a?|ab)[a-z]{1,24}`, `key=[^a-z]{1,32}!`, `key=[\x00\x80-\xff]{1,32}!`, `key=a?a??a?b`}
	b := combinedRegexBuilder{nfa: combinedRegexNFA{states: []combinedRegexState{{}}}, edges: make(map[combinedRegexEdge]int)}
	var patterns []RegexPattern
	var decoder combinedRegexDecoder
	for _, expression := range expressions {
		for _, modifier := range []string{"", "nocase"} {
			p := mustCompileStreamingProgram(f, fmt.Sprintf(`rule r {strings:$a=/%s/ %s condition:$a}`, expression, modifier))
			pattern := p.Rules[0].RegexPatterns["$a"]
			instructions, ok := decoder.decode(pattern)
			if !ok || !b.add(instructions, sharedAutomatonEntry{}, pattern.Flags&regex.FlagsGreedy != 0) {
				f.Fatal("build", expression)
			}
			patterns = append(patterns, pattern)
		}
	}
	f.Add([]byte("!"), byte('a'), byte(32))
	f.Add([]byte("ab!"), byte(255), byte(16))
	f.Fuzz(func(t *testing.T, tail []byte, value, size byte) {
		data := append([]byte("key="), bytes.Repeat([]byte{value}, int(size)%64)...)
		data = append(data, tail[:min(len(tail), 128)]...)
		scratch := combinedRegexScratch{}
		for _, input := range [][]byte{data, bytes.ToUpper(data), tail[:min(len(tail), 128)]} {
			b.nfa.match(input, &scratch, nil)
			for i, pattern := range patterns {
				matched, _, end := regex.ExecMatchBatch(nil, pattern.Code, input, pattern.Flags, 0)
				if (scratch.ends[i] > 0) != matched || matched && scratch.ends[i] != end {
					t.Fatalf("pattern=%d input=%q got=%d want=%t/%d", i, input, scratch.ends[i], matched, end)
				}
			}
		}
	})
}

func TestCombinedRegexCandidateBatch(t *testing.T) {
	p := mustCompileStreamingProgram(t, combinedNFASource(16, "!"))
	scanner := p.NewScanner()
	defer scanner.Close()
	data := []byte("key=" + strings.Repeat("a", 20) + "! key=" + strings.Repeat("a", 24) + "!")
	if _, err := scanner.Scan(data); err != nil {
		t.Fatal(err)
	}
	if len(scanner.touchedPrefilterCandidates) != 1 {
		t.Fatalf("candidate lists=%d want one shared batch", len(scanner.touchedPrefilterCandidates))
	}
	leader := scanner.touchedPrefilterCandidates[0]
	if len(scanner.prefilterCandidates[leader]) != 2 {
		t.Fatal("candidate offsets were duplicated or lost")
	}
}

func TestCombinedRegexSingleRuleConjunction(t *testing.T) {
	var source strings.Builder
	source.WriteString("rule r {strings:")
	for i := range 8 {
		fmt.Fprintf(&source, "$a%d=/key=[a-z]{16,%d}!/ ", i, 32+i)
	}
	source.WriteString("condition:all of them}")
	p := mustCompileStreamingProgram(t, source.String())
	result, err := p.Scan([]byte("key=" + strings.Repeat("a", 24) + "!"))
	if err != nil || len(result.MatchedRules) != 1 {
		t.Fatalf("premature empty-cache rejection: %v %v", result, err)
	}
}

func TestCombinedRegexGroupingBudget(t *testing.T) {
	p := mustCompileStreamingProgram(t, combinedNFASource(1024, "!"))
	grouped, total := 0, 0
	seen := make(map[*combinedRegexNFA]bool)
	for _, entry := range p.sharedLookup {
		n := entry.combined
		if n == nil {
			continue
		}
		grouped++
		if seen[n] {
			continue
		}
		seen[n] = true
		total += len(n.states)
		for _, state := range n.states {
			total += len(state.accepts)
		}
	}
	if grouped != 1024 || total > maxCombinedRegexProgramStates {
		t.Fatalf("grouped=%d states+accepts=%d", grouped, total)
	}
	var source strings.Builder
	for i := range 4 {
		fmt.Fprintf(&source, "rule r%d {strings:$a=/key=[a-%c]{32}!/ condition:$a}\n", i, 'p'+i)
	}
	p = mustCompileStreamingProgram(t, source.String())
	for _, entry := range p.sharedLookup {
		if entry.combined != nil {
			t.Fatal("grouped patterns with little transition sharing")
		}
	}
}
