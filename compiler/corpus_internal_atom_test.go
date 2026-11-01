package compiler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestCorpusInternalAtomSelection(t *testing.T) {
	var source strings.Builder
	for i := range minSharedNonTextEntries {
		atom := "abcdefgh"
		if i%2 == 1 {
			atom = "qrstuvwx"
		}
		fmt.Fprintf(&source, "rule r%d {strings:$a=/key=[a-z]{4}%s[0-9]{%d}/ condition:$a}\n", i, atom, i+1)
	}
	p := mustCompileStreamingProgram(t, source.String())
	choices := corpusSharedAtoms(p.Rules)
	if len(choices) != minSharedNonTextEntries {
		t.Fatalf("selected %d internal atoms", len(choices))
	}
	if len(p.sharedLookup) != minSharedNonTextEntries {
		t.Fatal("missing shared atom entries")
	}
	for i, entry := range p.sharedLookup {
		pattern := p.Rules[entry.RuleIndex].RegexPatterns["$a"]
		if entry.AtomOffset != 8 || entry.AtomMaxOffset != 8 || !bytes.Equal(p.sharedAutomaton.strings[i].Data, pattern.atom) {
			t.Fatal("builder did not install the selected atom")
		}
	}
	for _, rule := range p.Rules {
		pattern := rule.RegexPatterns["$a"]
		atom := choices[pattern.cacheKey]
		if !bytes.Equal(atom.data, pattern.atom) || atom.minOffset != 8 || atom.maxOffset != 8 {
			t.Fatalf("wrong internal atom: %+v", atom)
		}
		if got := selectSharedRegexAtoms(pattern)[0]; string(got.data) != "key=" {
			t.Fatal("per-pattern selection changed")
		}
	}
	duplicates := append(slices.Clone(p.Rules), p.Rules[0], p.Rules[0])
	if !reflect.DeepEqual(choices, corpusSharedAtoms(duplicates)) {
		t.Fatal("duplicate verifier changed frequency")
	}
	reverse := slices.Clone(p.Rules)
	slices.Reverse(reverse)
	if !reflect.DeepEqual(choices, corpusSharedAtoms(reverse)) {
		t.Fatal("rule order changed selection")
	}
	p.Rules[1].IsDead = true
	if len(corpusSharedAtoms(p.Rules)) != 0 {
		t.Fatal("dead rule counted")
	}
	p.Rules[1].IsDead = false
	p.Rules[1].DeadStrings = map[string]bool{"$a": true}
	if len(corpusSharedAtoms(p.Rules)) != 0 {
		t.Fatal("dead string counted")
	}
}

func TestCorpusInternalAtomEligibility(t *testing.T) {
	for _, test := range []struct {
		name   string
		prefix string
		atoms  [2]string
		min    int
		max    int
		want   int
	}{
		{"rare", "key=", [2]string{"abcdefgh", "qrstuvwx"}, 8, 8, minSharedNonTextEntries},
		{"shared", "key=", [2]string{"abcdefgh", "abcdefgh"}, 8, 8, 0},
		{"case aliases", "key=", [2]string{"AbCdEfGh", "aBcDeFgH"}, 8, 8, 0},
		{"NUL padding", "key=", [2]string{"key=\x00\x00\x00\x00", "qrstuvwx"}, 8, 8, minSharedNonTextEntries},
		{"variable offset", "key=", [2]string{"abcdefgh", "qrstuvwx"}, 8, 12, 0},
		{"unbounded offset", "key=", [2]string{"abcdefgh", "qrstuvwx"}, 8, -1, 0},
		{"inside prefix", "key=", [2]string{"abcdefgh", "qrstuvwx"}, 2, 2, 0},
		{"shorter", "key=", [2]string{"abc", "xyz"}, 8, 8, 0},
		{"shorter high quality", "key=", [2]string{"\x00\x01\x02", "\x03\x04\x05"}, 8, 8, 0},
		{"lower quality", "!@#$%^&*", [2]string{"abcdefgh", "qrstuvwx"}, 8, 8, 0},
		{"no prefix", "", [2]string{"abcdefgh", "qrstuvwx"}, 8, 8, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			rules := make([]*CompiledRule, minSharedNonTextEntries)
			for i := range rules {
				rules[i] = &CompiledRule{RegexPatterns: map[string]RegexPattern{"$a": {
					cacheKey: strconv.Itoa(i), prefix: []byte(test.prefix), atom: []byte(test.atoms[i%2]),
					atomMinOffset: test.min, atomMaxOffset: test.max,
				}}}
			}
			if got := corpusSharedAtoms(rules); len(got) != test.want {
				t.Fatalf("selections=%d, want %d", len(got), test.want)
			}
		})
	}
}

func TestCorpusInternalSmallCorpusKeepsSharedPass(t *testing.T) {
	var source strings.Builder
	for i := range 5 {
		fmt.Fprintf(&source, "rule small%d {strings:$a=/key=[a-z]{4}%cabcdefg/ condition:$a}\n", i, 'v'+i)
	}
	p := mustCompileStreamingProgram(t, source.String())
	if len(corpusSharedAtoms(p.Rules)) != 0 || len(p.sharedLookup) != 5 {
		t.Fatal("new atom roots disabled the small shared pass")
	}
	for _, info := range p.sharedAutomaton.strings {
		if string(info.Data) != "key=" {
			t.Fatal("small corpus changed prefix")
		}
	}
}

func TestCorpusInternalLargeCorpusMatches(t *testing.T) {
	p := mustCompileStreamingProgram(t, corpusInternalSource(10000))
	s := p.NewScanner()
	defer s.Close()
	for _, test := range []struct {
		data string
		want bool
	}{
		{"key=abcdTOKEN_0000999942", true},
		{"key=abcdnot_a_token status=200", false},
		{"key=1234TOKEN_0000999942", false},
		{"level=info request completed status=200", false},
		{"key=abcdTOKEN_0000999942", true},
	} {
		got, err := s.Matches([]byte(test.data))
		if err != nil || got != test.want {
			t.Fatalf("%q: matched=%t, want=%t, err=%v", test.data, got, test.want, err)
		}
	}
}

func TestCorpusInternalAtomScanParity(t *testing.T) {
	for _, modifier := range []string{"", "nocase", "wide", "ascii wide fullword"} {
		t.Run(modifier, func(t *testing.T) {
			var source strings.Builder
			for i := range 40 {
				fmt.Fprintf(&source, "rule internal_%d {strings:$a=/key=[a-z]{4}TOKEN_%08d[0-9]{2}/ %s condition:#a>0}\n", i, i, modifier)
			}
			p := mustCompileStreamingProgram(t, source.String())
			if len(corpusSharedAtoms(p.Rules)) != 40 {
				t.Fatal("fixture did not select internal atoms")
			}
			encoded, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			reloaded, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}
			hit := []byte("!key=abcdTOKEN_0000003942!key=wxyzTOKEN_0000000173!")
			inputs := [][]byte{hit, bytes.ToUpper(hit), widenRegexPrefix(hit), []byte("key=1234TOKEN_0000003942"), []byte("key=abcdnot_a_token"), nil, hit}
			for _, program := range []*CompiledProgram{p, reloaded} {
				if len(corpusSharedAtoms(program.Rules)) != 40 {
					t.Fatal("reload lost internal atoms")
				}
				s := program.NewScanner(WithMatchData(128), WithStreamChunkSize(7), WithStreamEarlyTermination(false))
				defer s.Close()
				for _, data := range inputs {
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
					}
					streamed, err := s.ScanReader(bytes.NewReader(data))
					if err != nil || !reflect.DeepEqual(result.Matches, streamed.Matches) {
						t.Fatalf("reader mismatch: %v", err)
					}
					matched, err := s.Matches(data)
					if err != nil || matched != (len(result.MatchedRules) != 0) {
						t.Fatalf("boolean mismatch: %v", err)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := s.MatchesWithContext(ctx, hit); !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
			}
		})
	}
}

func TestCorpusInternalASCIIFoldedAtom(t *testing.T) {
	var source strings.Builder
	source.WriteString(`
rule a {strings:$a=/key=[0-9]{2}[aA][bB][cC][dD][eE][fF][gG][hH]/ condition:$a}
rule b {strings:$a=/key=[0-9]{2}[qQ][rR][sS][tT][uU][vV][wW][xX]/ condition:$a}`)
	for i := range minSharedNonTextEntries - 2 {
		fmt.Fprintf(&source, "rule extra%d {strings:$a=/key=[0-9]{2}TOKEN_%08d/ condition:$a}\n", i, i)
	}
	p := mustCompileStreamingProgram(t, source.String())
	choices := corpusSharedAtoms(p.Rules)
	if len(choices) != minSharedNonTextEntries {
		t.Fatal("folded internal atoms not selected")
	}
	for _, rule := range p.Rules[:2] {
		if !choices[rule.RegexPatterns["$a"].cacheKey].asciiNoCase {
			t.Fatal("folded flag lost")
		}
	}
	for _, data := range []string{"key=12aBcDeFgH", "key=12QrStUvWx"} {
		result, err := p.Scan([]byte(data))
		if err != nil || len(result.MatchedRules) != 1 {
			t.Fatalf("folded match: %+v, %v", result, err)
		}
	}
	// Atom-local folding must not make the case-sensitive prefix nocase.
	scanner := p.NewScanner()
	defer scanner.Close()
	matched, err := scanner.Matches([]byte("KEY=12aBcDeFgH"))
	if err != nil || matched {
		t.Fatalf("prefix folding leaked: %t, %v", matched, err)
	}
}

func FuzzCorpusInternalAtoms(f *testing.F) {
	f.Add([]byte("key=abcdTOKEN_0000003942"), uint16(0))
	f.Add([]byte("key=1234TOKEN_0000000142"), uint16(31))
	p := mustCompileStreamingProgram(f, corpusInternalSource(40))
	f.Fuzz(func(t *testing.T, data []byte, offset uint16) {
		data = data[:min(len(data), 2048)]
		input := append(bytes.Clone(data), make([]byte, 32)...)
		copy(input[int(offset)%len(input):], "key=abcdTOKEN_0000003942")
		result, err := p.Scan(input)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range p.Rules {
			linear := buildLinearRegexContext(rule, input)
			want := matchRangesInOrder(linear.Matches["$a"])
			linear.Release()
			if got := matchRangesInOrder(result.Matches[rule.Name]["$a"]); !slices.Equal(got, want) {
				t.Fatal("internal atom/linear mismatch")
			}
		}
	})
}
