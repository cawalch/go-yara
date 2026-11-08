package compiler

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestCorpusPrefixAtomSelection(t *testing.T) {
	p := mustCompileStreamingProgram(t, `
 rule one {strings:$a=/provider_abcd=api_key=[a-z]{16}/ condition:$a}
 rule two {strings:$a=/provider_wxyz=api_key=[a-z]{16}/ condition:$a}
 `)
	choices := corpusPrefixAtoms(p.Rules)
	if len(choices) != 2 {
		t.Fatalf("changed atoms=%d, want 2", len(choices))
	}
	for _, rule := range p.Rules {
		pattern := rule.RegexPatterns["$a"]
		old := selectSharedRegexAtoms(pattern)[0]
		got := choices[pattern.cacheKey]
		if got.minOffset != 12 || got.maxOffset != 12 || !bytes.Equal(got.data, pattern.prefix[12:20]) || got.score != old.score {
			t.Fatalf("wrong prefix selection: %+v, old %+v", got, old)
		}
	}
	// Repeating an identical verifier in more rules must not change frequency.
	duplicate := append(slices.Clone(p.Rules), p.Rules[0], p.Rules[0])
	if !reflect.DeepEqual(choices, corpusPrefixAtoms(duplicate)) {
		t.Fatal("duplicate verifier changed selection")
	}
	// Dead rules and dead strings must not influence the live corpus.
	p.Rules[1].IsDead = true
	if len(corpusPrefixAtoms(p.Rules)) != 0 {
		t.Fatal("dead rule counted")
	}
	p.Rules[1].IsDead = false
	p.Rules[1].DeadStrings = map[string]bool{"$a": true}
	if len(corpusPrefixAtoms(p.Rules)) != 0 {
		t.Fatal("dead string counted")
	}
}

func TestCorpusPrefixAtomScanParity(t *testing.T) {
	var source strings.Builder
	var positive []byte
	for i := range 40 {
		modifiers := ""
		token := corpusAtomPrefix(i) + "abcdefghijklmnop"
		switch i % 4 {
		case 1:
			modifiers = " nocase"
			token = strings.ToUpper(token)
		case 2:
			modifiers = " wide"
		case 3:
			modifiers = " ascii wide fullword"
		}
		fmt.Fprintf(&source, "rule corpus_%d {strings:$a=/%s[a-z]{16}/%s condition:$a}\n", i, corpusAtomPrefix(i), modifiers)
		positive = append(positive, '!')
		if i%4 >= 2 {
			positive = append(positive, widenRegexPrefix([]byte(token))...)
		} else {
			positive = append(positive, token...)
		}
		positive = append(positive, '!')
	}
	p := mustCompileStreamingProgram(t, source.String())
	if len(corpusPrefixAtoms(p.Rules)) == 0 {
		t.Fatal("test did not change atoms")
	}
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for name, program := range map[string]*CompiledProgram{"compiled": p, "reloaded": reloaded} {
		for index, data := range [][]byte{positive, []byte("provider_none=api_key=abcdefghijklmnop"), positive[:len(positive)-8], []byte("clean input")} {
			t.Run(fmt.Sprintf("%s/%d", name, index), func(t *testing.T) {
				s := program.NewScanner(WithMatchData(128), WithStreamChunkSize(7), WithStreamEarlyTermination(false))
				defer s.Close()
				result, err := s.Scan(data)
				if err != nil {
					t.Fatal(err)
				}
				for _, rule := range program.Rules {
					linear := buildLinearRegexContext(rule, data)
					got := matchRangesInOrder(result.Matches[rule.Name]["$a"])
					want := matchRangesInOrder(linear.Matches["$a"])
					linear.Release()
					if !slices.Equal(got, want) {
						t.Fatalf("%s: shared=%v linear=%v", rule.Name, got, want)
					}
					if index == 0 && len(got) != 1 {
						t.Fatalf("%s positive matches=%v", rule.Name, got)
					}
				}
				streamed, err := s.ScanReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(result.Matches, streamed.Matches) {
					t.Fatal("reader matches differ")
				}
				blocks := program.NewBlockScanner(WithMatchData(128))
				defer blocks.Close()
				if err := blocks.Scan(0, data); err != nil {
					t.Fatal(err)
				}
				blocked, err := blocks.Finish()
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(result.Matches, blocked.Matches) {
					t.Fatal("block matches differ")
				}
				fast := program.NewScanner(WithFastScan())
				defer fast.Close()
				matched, err := fast.Matches(data)
				if err != nil {
					t.Fatal(err)
				}
				if matched != (len(result.MatchedRules) > 0) {
					t.Fatal("fast boolean mismatch")
				}
			})
		}
	}
}

func TestCorpusPrefixKeepsQualityAndCovers(t *testing.T) {
	for _, source := range []string{
		`rule a {strings:$a=/abcd-request-header:[a-z]+/ condition:$a}
   rule b {strings:$a=/wxyz-request-header:[a-z]+/ condition:$a}`,
		`rule a {strings:$a=/(provider_abcd=api_key=|other_wxyz=api_key=)[a-z]+/ condition:$a}
   rule b {strings:$a=/(provider_wxyz=api_key=|other_abcd=api_key=)[a-z]+/ condition:$a}`,
		`rule a {strings:$a=/api_key=[a-z]+/ condition:$a}
   rule b {strings:$a=/api_key=[0-9]+/ condition:$a}`,
	} {
		p := mustCompileStreamingProgram(t, source)
		if got := corpusPrefixAtoms(p.Rules); len(got) != 0 {
			t.Fatalf("changed a lower-quality or non-prefix cover: %+v", got)
		}
	}
	if corpusAtomKey([]byte("Api_KEY=")) != corpusAtomKey([]byte("api_key=")) {
		t.Fatal("ASCII case variants must share a frequency key")
	}
}

func TestCorpusPrefixStopsAfterReducingSharing(t *testing.T) {
	var source strings.Builder
	for i := range 32 {
		last := 'd'
		if i >= 16 {
			last = 'z'
		}
		fmt.Fprintf(&source, "rule r%d {strings:$a=/provider_ab%c%c=api_key=[a-z]+/ condition:$a}\n", i, 'a'+i%16, last)
	}
	p := mustCompileStreamingProgram(t, source.String())
	choices := corpusPrefixAtoms(p.Rules)
	if len(choices) != 32 {
		t.Fatalf("changed atoms=%d, want 32", len(choices))
	}
	for _, atom := range choices {
		if atom.minOffset != 12 {
			t.Fatalf("selected %q at %d; two shared windows suffice", atom.data, atom.minOffset)
		}
	}
}

func TestCorpusPrefixWideAtomOffsetUnits(t *testing.T) {
	source := corpusAtomSource(40) + `rule shifted {strings:$a=/provider_ryoqfi=api_key=(xy|z){1,3}/ wide condition:$a}`
	p := mustCompileStreamingProgram(t, source)
	rule, _ := p.GetRuleByName("shifted")
	pattern := rule.RegexPatterns["$a"]
	atom := corpusPrefixAtoms(p.Rules)[pattern.cacheKey]
	// The selected window's byte offset equals the verifier atom's character
	// offset. Their checks must not be confused merely because both are 16.
	if atom.minOffset != 8 || pattern.atomMinOffset != 16 {
		t.Fatalf("wrong regression setup: prefix=%d verifier=%d", atom.minOffset, pattern.atomMinOffset)
	}
	data := widenRegexPrefix([]byte("provider_ryoqfi=api_key=xyzz"))
	result, err := p.Scan(data)
	if err != nil {
		t.Fatal(err)
	}
	matches := result.Matches["shifted"]["$a"]
	if len(matches) != 1 || matches[0].Offset != 0 || matches[0].Length != len(data) {
		t.Fatalf("wide match lost: %+v", matches)
	}
}

func TestAtomEntropy(t *testing.T) {
	repetitive := atomEntropy([]byte("AAAAAAAA"))
	underscores := atomEntropy([]byte("________"))
	token := atomEntropy([]byte("password"))
	highEntropy := atomEntropy([]byte("xoxb-987"))
	mixedKey := atomEntropy([]byte("AKIA1234"))
	githubToken := atomEntropy([]byte("ghp_1234"))

	if repetitive >= highEntropy {
		t.Fatalf("repetitive atom score %d >= high entropy score %d", repetitive, highEntropy)
	}
	if underscores >= highEntropy {
		t.Fatalf("underscores score %d >= high entropy score %d", underscores, highEntropy)
	}
	if token >= highEntropy {
		t.Fatalf("common word score %d >= high entropy score %d", token, highEntropy)
	}
	if mixedKey <= repetitive {
		t.Fatalf("mixed key score %d <= repetitive score %d", mixedKey, repetitive)
	}
	if githubToken <= token {
		t.Fatalf("github token score %d <= common token score %d", githubToken, token)
	}
}

func TestCorpusPrefixEntropyWeightedHoisting(t *testing.T) {
	// A corpus where rules share saturated tokens but each has a unique high-entropy token
	count := 64
	p := mustCompileStreamingProgram(t, corpusAtomSource(count))
	choices := corpusPrefixAtoms(p.Rules)
	if len(choices) == 0 {
		t.Fatal("corpus prefix atom selection produced no choices")
	}

	// Verify that the selected atom is NOT the saturated "=api_key=" suffix
	for _, rule := range p.Rules {
		pattern := rule.RegexPatterns["$a"]
		atom, ok := choices[pattern.cacheKey]
		if !ok {
			t.Fatalf("rule %s had no selected prefix atom", rule.Name)
		}
		if string(atom.data) == "api_key=" || string(atom.data) == "=api_key" {
			t.Fatalf("rule %s chose saturated atom %q", rule.Name, atom.data)
		}
	}

	// Scanning clean data must reject quickly
	s := p.NewScanner()
	defer s.Close()
	clean := []byte("level=info request completed status=200")
	matched, err := s.Matches(clean)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("clean log matched rules unexpectedly")
	}

	// Shared token with non-matching identifier must not match any rule
	nonMatchingToken := []byte("provider_none=api_key=abcdefghijklmnop")
	matched, err = s.Matches(nonMatchingToken)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Fatal("non-matching token matched rules unexpectedly")
	}

	// Authentic match must match exactly
	targetRuleIndex := count - 1
	matchingToken := []byte(corpusAtomPrefix(targetRuleIndex) + "abcdefghijklmnop")
	matched, err = s.Matches(matchingToken)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatalf("authentic rule %d input failed to match", targetRuleIndex)
	}
}

func TestLargeCorpusCompactPrefilterRejection(t *testing.T) {
	p := mustCompileStreamingProgram(t, corpusAtomSource(128))
	if p.compactPrefilter == nil {
		t.Fatal("large regex corpus must activate compact prefilter gate")
	}
	s := p.NewScanner()
	defer s.Close()

	clean := []byte("level=info request completed status=200")
	if !s.compactPrefilterRejects(context.Background(), clean) {
		t.Fatal("clean log was not rejected by compact prefilter gate")
	}
}
