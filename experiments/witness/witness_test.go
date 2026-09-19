package witness

import (
	"bytes"
	"math"
	"math/rand"
	"testing"
)

func referenceMatch(rules []Rule, data []byte) bool {
	for _, rule := range rules {
		all := true
		for _, pattern := range rule.All {
			found := false
			for _, sequence := range pattern.Any {
				for start := 0; start <= len(data); start++ {
					if referenceSequence(sequence, data, start) {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			all = all && found
		}
		if all {
			return true
		}
	}
	return false
}

func referenceSequence(sequence Sequence, data []byte, start int) bool {
	if len(sequence) == 0 {
		return true
	}
	term := sequence[0]
	if len(term.Literal) != 0 {
		if len(term.Literal) > len(data)-start {
			return false
		}
		for i, want := range term.Literal {
			got := data[start+i]
			if term.NoCase {
				if got >= 'A' && got <= 'Z' {
					got += 'a' - 'A'
				}
				if want >= 'A' && want <= 'Z' {
					want += 'a' - 'A'
				}
			}
			if got != want {
				return false
			}
		}
		return referenceSequence(sequence[1:], data, start+len(term.Literal))
	}
	for length := 0; length <= term.Max && length <= len(data)-start; length++ {
		if length > 0 {
			b := data[start+length-1]
			if term.Set[b/64]&(uint64(1)<<(b%64)) == 0 {
				break
			}
		}
		if length >= term.Min && referenceSequence(sequence[1:], data, start+length) {
			return true
		}
	}
	return false
}

func checkWitness(t testing.TB, rules []Rule, inputs [][]byte) {
	t.Helper()
	program, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	scanner := program.NewScanner()
	scanner.budgetLimit = 1 << 20
	for _, data := range inputs {
		want := NoMatch
		if referenceMatch(rules, data) {
			want = Match
		}
		if got := scanner.Match(data); got != want {
			t.Fatalf("input %x: got %v want %v; rules %+v", data, got, want, rules)
		}
	}
}

func TestWitnessLiteralAlignments(t *testing.T) {
	for _, length := range []int{1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31} {
		literal := make([]byte, length)
		for i := range literal {
			literal[i] = byte(65 + i)
		}
		rules := []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: literal}}}}}}}
		program, err := Compile(rules)
		if err != nil {
			t.Fatal(err)
		}
		scanner := program.NewScanner()
		for offset := 0; offset < 32; offset++ {
			for tail := 0; tail < 16; tail++ {
				data := append(bytes.Repeat([]byte{'~'}, offset), literal...)
				data = append(data, bytes.Repeat([]byte{'~'}, tail)...)
				if !referenceMatch(rules, data) || scanner.Match(data) != Match {
					t.Fatalf("length=%d offset=%d tail=%d: missing known literal", length, offset, tail)
				}
				data[offset+length-1] = 0xff
				if referenceMatch(rules, data) || scanner.Match(data) != NoMatch {
					t.Fatalf("length=%d offset=%d tail=%d: accepted near miss", length, offset, tail)
				}
			}
		}
		checkWitness(t, rules, [][]byte{nil, literal[:len(literal)-1]})
	}
}

func TestWitnessSequences(t *testing.T) {
	anyByte := [4]uint64{math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64}
	var digits [4]uint64
	for b := byte('0'); b <= '9'; b++ {
		digits[b/64] |= uint64(1) << (b % 64)
	}
	for _, test := range []struct {
		name    string
		rules   []Rule
		yes, no [][]byte
	}{
		{"binary", []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: []byte{0, 0xff, 0x80}}}}}}}}, [][]byte{{0, 0xff, 0x80}}, [][]byte{{0x20, 0xff, 0x80}, {0, 0xff, 0xa0}, {0, 0xff}}},
		{"nocase", []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: []byte("aBc@"), NoCase: true}}}}}}}, [][]byte{[]byte("ABC@"), []byte("abc@")}, [][]byte{[]byte("abc`"), []byte("Abd@")}},
		{"sensitive", []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: []byte("aBc")}}}}}}}, [][]byte{[]byte("aBc")}, [][]byte{[]byte("abc"), []byte("ABC")}},
		{"overlap", []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: []byte("ababa")}}, {{Literal: []byte("abaca")}}}}}}}, [][]byte{[]byte("abababaca"), []byte("abaca")}, [][]byte{[]byte("ababx"), []byte("abac")}},
		{"conjunction", []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: []byte("left")}}}}, {Any: []Sequence{{{Literal: []byte("right")}}}}}}}, [][]byte{[]byte("left right"), []byte("right left"), []byte("rightleft")}, [][]byte{[]byte("left"), []byte("right")}},
		{"shared", []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: []byte("prefixAend")}}, {{Literal: []byte("prefixBend")}}}}}}, {All: []Pattern{{Any: []Sequence{{{Literal: []byte("prefixAend")}}, {{Literal: []byte("otherAend")}}}}}}}, [][]byte{[]byte("prefixAend"), []byte("prefixBend"), []byte("otherAend")}, [][]byte{[]byte("prefixCend"), []byte("otherBend")}},
		{"bounded", []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: []byte("<")}, {Set: anyByte, Min: 1, Max: 3}, {Literal: []byte("ANCHOR123")}, {Set: digits, Min: 1, Max: 2}, {Literal: []byte("!")}}}}}}}, [][]byte{[]byte("<xANCHOR1234!"), []byte("<xyzANCHOR12345!")}, [][]byte{[]byte("<ANCHOR1234!"), []byte("<xxxxANCHOR1234!"), []byte("<xANCHOR123456!"), []byte("<xANCHOR123x!")}},
		{"optional", []Rule{{All: []Pattern{{Any: []Sequence{{{Set: digits, Min: 0, Max: 2}, {Literal: []byte("TOKEN")}, {Set: digits, Min: 0, Max: 2}}}}}}}, [][]byte{[]byte("TOKEN"), []byte("12TOKEN34")}, [][]byte{[]byte("TOKE"), nil}},
		{"huge bounds", []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: []byte("Q")}, {Set: anyByte, Max: math.MaxInt}, {Set: anyByte, Max: math.MaxInt}, {Literal: []byte("ANCHOR123")}, {Set: anyByte, Max: math.MaxInt}, {Literal: []byte("Z")}}}}}}}, [][]byte{[]byte("QxANCHOR123yZ"), []byte("QANCHOR123Z")}, [][]byte{[]byte("QANCHOR123"), []byte("ANCHOR123Z")}},
		{"zero run", []Rule{{All: []Pattern{{Any: []Sequence{{{}, {Literal: []byte("X")}, {}}}}}}}, [][]byte{[]byte("X")}, [][]byte{nil, []byte("Y")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, data := range test.yes {
				if !referenceMatch(test.rules, data) {
					t.Fatalf("oracle rejected known positive %x", data)
				}
			}
			for _, data := range test.no {
				if referenceMatch(test.rules, data) {
					t.Fatalf("oracle accepted known negative %x", data)
				}
			}
			inputs := append(append([][]byte{}, test.yes...), test.no...)
			for offset := 1; offset < 32; offset++ {
				for _, data := range test.yes {
					inputs = append(inputs, append(bytes.Repeat([]byte{0xfe}, offset), data...))
				}
			}
			inputs = append(inputs, test.yes...)
			checkWitness(t, test.rules, inputs)
		})
	}
}

func TestWitnessCompileBoundaries(t *testing.T) {
	literal := Term{Literal: []byte("token")}
	var all [4]uint64
	for i := range all {
		all[i] = math.MaxUint64
	}
	for _, sequence := range []Sequence{
		nil, {}, {{Set: all, Min: 1, Max: 2}}, {literal, {Set: all, Min: -1, Max: 1}},
		{literal, {Set: all, Min: 2, Max: 1}}, {literal, {Min: 0, Max: 1}},
		append(make(Sequence, 64), literal),
	} {
		if _, err := Compile([]Rule{{All: []Pattern{{Any: []Sequence{sequence}}}}}); err == nil {
			t.Fatalf("accepted invalid or unanchorable sequence %+v", sequence)
		}
	}
	for _, rules := range [][]Rule{
		{{All: []Pattern{{}}}},
		{{All: []Pattern{{Any: []Sequence{{literal}, {{Set: all, Max: 1}}}}}}},
		{{}, {All: []Pattern{{}}}},
	} {
		if _, err := Compile(rules); err == nil {
			t.Fatalf("accepted unsupported rules %+v", rules)
		}
	}
	checkWitness(t, nil, [][]byte{nil, []byte("anything")})
	checkWitness(t, []Rule{{}}, [][]byte{nil, []byte("anything")})
	checkWitness(t, []Rule{{All: []Pattern{{Any: []Sequence{append(make(Sequence, 63), literal)}}}}}, [][]byte{[]byte("token"), []byte("other")})
}

func TestWitnessBudgetAndOwnership(t *testing.T) {
	literal := []byte("anchor123")
	rules := []Rule{{All: []Pattern{{Any: []Sequence{{{Literal: literal}}}}, {Any: []Sequence{{{Literal: []byte("second456")}}}}}}}
	program, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	literal[0] = 'X'
	scanner := program.NewScanner()
	scanner.budgetLimit = 1
	if got := scanner.Match([]byte("anchor123 second456")); got != Unknown {
		t.Fatalf("exhausted matching query = %v, want Unknown", got)
	}
	scanner.budgetLimit = 1 << 20
	for _, data := range [][]byte{[]byte("anchor123 second456"), []byte("second456 anchor123")} {
		if got := scanner.Match(data); got != Match {
			t.Fatalf("ownership/budget reset: %v", got)
		}
	}
	for _, data := range [][]byte{nil, []byte("Xnchor123 second456"), []byte("anchor123")} {
		if got := scanner.Match(data); got != NoMatch {
			t.Fatalf("nonmatch = %v for %q", got, data)
		}
	}
	if stats := program.Stats(); stats.Rules != 1 || stats.Sequences != 2 || stats.Signatures < 1 {
		t.Fatalf("stats %+v", stats)
	}
}

func TestWitnessRandomParity(t *testing.T) {
	r := rand.New(rand.NewSource(70419))
	for iteration := 0; iteration < 120; iteration++ {
		var rules []Rule
		for ruleIndex := 0; ruleIndex < 1+r.Intn(3); ruleIndex++ {
			var rule Rule
			for patternIndex := 0; patternIndex < 1+r.Intn(3); patternIndex++ {
				var pattern Pattern
				for branch := 0; branch < 1+r.Intn(3); branch++ {
					literal := make([]byte, 1+r.Intn(17))
					for i := range literal {
						literal[i] = []byte("aAbBcC@`\x00\xff")[r.Intn(10)]
					}
					var set [4]uint64
					for _, b := range []byte{'a', 'b', 0, 0xff} {
						set[b/64] |= uint64(1) << (b % 64)
					}
					pattern.Any = append(pattern.Any, Sequence{{Set: set, Max: r.Intn(3)}, {Literal: literal, NoCase: r.Intn(2) == 0}, {Set: set, Max: r.Intn(3)}})
				}
				rule.All = append(rule.All, pattern)
			}
			rules = append(rules, rule)
		}
		var inputs [][]byte
		for sample := 0; sample < 8; sample++ {
			data := make([]byte, r.Intn(96))
			r.Read(data)
			if sample%2 == 0 {
				for _, pattern := range rules[0].All {
					data = append(data, pattern.Any[0][1].Literal...)
				}
				if !referenceMatch(rules, data) {
					t.Fatal("constructed random positive rejected by oracle")
				}
			}
			inputs = append(inputs, data)
		}
		checkWitness(t, rules, inputs)
	}
}

func FuzzWitnessParity(f *testing.F) {
	f.Add([]byte("prefix AbC suffix"), []byte("abc"))
	f.Add([]byte{0, 0xff, 0x80}, []byte{0, 0xff})
	f.Add([]byte("ababababa"), []byte("ababa"))
	f.Fuzz(func(t *testing.T, data, literal []byte) {
		if len(data) > 256 {
			data = data[:256]
		}
		if len(literal) == 0 {
			return
		}
		if len(literal) > 31 {
			literal = literal[:31]
		}
		alternate := bytes.Clone(literal)
		alternate[len(alternate)-1] ^= 0x40
		all := [4]uint64{math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64}
		rules := []Rule{{All: []Pattern{{Any: []Sequence{
			{{Set: all, Min: int(literal[0] & 1), Max: 2}, {Literal: literal, NoCase: literal[0]&2 != 0}},
			{{Literal: []byte("!")}, {Set: all, Max: 3}, {Literal: alternate}},
		}}}}}
		positive := append(append(append([]byte{}, data...), 0), literal...)
		other := append([]byte("!xy"), alternate...)
		if !referenceMatch(rules, positive) || !referenceMatch(rules, other) {
			t.Fatal("oracle rejected constructed fuzz positive")
		}
		checkWitness(t, rules, [][]byte{data, positive, other, nil})
	})
}
