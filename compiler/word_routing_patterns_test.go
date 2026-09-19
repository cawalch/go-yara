package compiler

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/ast"
	"github.com/cawalch/go-yara/internal/wordmatch"
	"github.com/cawalch/go-yara/regex"
)

func TestWordRoutingPatternShape(t *testing.T) {
	tests := []struct {
		source              string
		alternatives, terms int
	}{
		{`/abcdefghijklmnop(foo|bar)/`, 2, 1},
		{`/abcdefghijklmnop(|bar)/`, 2, 1},
		{`/abcdefghijklmnop[0-9]{2,4}END/`, 1, 3},
		{`/abcdefghijklmnop.{0,4}END/s`, 1, 3},
		{`/abcdefghijklmnop[\x41]{1,1}/`, 1, 1},
		{`/[aA][bB][cC][dD][eE][fF][gG][hH][iI][jJ][kK][lL][mM][nN][oO][pP]/`, 1, 1},
		{`/abcdefghijklmnop[0-9]{0}END/`, 1, 1},
		{`/abcdefghijklmnop` + strings.Repeat(`(a|b)`, 6) + `/`, 64, 1},
		{`/abcdefghijklmnop` + strings.Repeat(`[0-9]`, 63) + `/`, 1, 64},
	}
	for _, test := range tests {
		t.Run(test.source, func(t *testing.T) {
			pattern, ok := wordRoutingPattern(&ast.String{Pattern: &ast.RegexPattern{Value: test.source}})
			if !ok || len(pattern.Any) != test.alternatives {
				t.Fatalf("conversion=%+v,%v", pattern, ok)
			}
			for _, sequence := range pattern.Any {
				if len(sequence) != test.terms {
					t.Fatalf("terms=%d want%d", len(sequence), test.terms)
				}
			}
		})
	}
	pattern, ok := wordRoutingPattern(&ast.String{Pattern: &ast.RegexPattern{Value: `/[aA][bB]/`}})
	if !ok || !pattern.Any[0][0].NoCase || !bytes.Equal(pattern.Any[0][0].Literal, []byte("AB")) {
		t.Fatalf("ASCII case pairs: %+v,%v", pattern, ok)
	}
}

func TestWordRoutingPatternDeclines(t *testing.T) {
	for _, source := range []string{
		`/abcdefghijklmnop.*/`, `/abcdefghijklmnop.+/`, `/abcdefghijklmnop[0-9]{1,}/`,
		`/abcdefghijklmnop[0-9]{1,65535}/`, `/^abcdefghijklmnop/`, `/abcdefghijklmnop$/`,
		`/abcdefghijklmnop\b/`, `/\Babcdefghijklmnop/`, `/abcdefghijklmnop/m`,
		`/abcdefghijklmnop\q/`, `/abcdefghijklmnop|[0-9]{3}/`, `/[0-9]{3}/`,
		`/abcdefghijklmnop(ab){1,2}/`, `/abcdefghijklmnop[0-9]{3,2}/`,
		`/abcdefghijklmnop` + strings.Repeat(`(a|b)`, 7) + `/`,
		`/abcdefghijklmnop` + strings.Repeat(`[0-9]`, 64) + `/`,
		`/` + strings.Repeat("a", 4097) + `/`,
	} {
		if _, ok := wordRoutingPattern(&ast.String{Pattern: &ast.RegexPattern{Value: source}}); ok {
			t.Errorf("accepted %s", source)
		}
	}
	for _, modifier := range []ast.StringModifierType{ast.StringModifierWide, ast.StringModifierFullword, ast.StringModifierPrivate, ast.StringModifierXor, ast.StringModifierBase64, ast.StringModifierBase64Wide, ast.StringModifierCapture} {
		for _, pattern := range []ast.Pattern{&ast.TextString{Value: "abcdefghijklmnop"}, &ast.RegexPattern{Value: `/abcdefghijklmnop/`}} {
			if _, ok := wordRoutingPattern(&ast.String{Pattern: pattern, Modifiers: []ast.StringModifier{{Type: modifier}}}); ok {
				t.Errorf("accepted modifier%d", modifier)
			}
		}
	}
	for _, str := range []*ast.String{nil, {}, {Pattern: &ast.TextString{}}, {Pattern: (*ast.RegexPattern)(nil)}, {Pattern: &ast.HexString{Value: "{ 41 }"}}} {
		if _, ok := wordRoutingPattern(str); ok {
			t.Errorf("accepted %+v", str)
		}
	}
}

func TestWordRoutingRegexByteParity(t *testing.T) {
	const anchor = "AbCdEfGhIjKlMnOp"
	patterns := []string{
		"/" + anchor + ".{0,4}Z/", "/" + anchor + ".{0,4}Z/s", "/" + anchor + ".Z/", "/" + anchor + ".Z/s", "/" + anchor + "[^a-z]{0,2}Z/i",
		"/" + anchor + "[a-z]{1,2}Z/i", "/" + anchor + "[\\x00-\\xff]{0,2}Z/",
		"/" + anchor + "[[:space:]]{1,2}Z/", "/" + anchor + "\\w{0,2}Z/i",
		"/" + anchor + "\\W{0,2}Z/", "/" + anchor + "\\d{0,2}Z/", "/" + anchor + "\\D{0,2}Z/",
		"/" + anchor + "\\s{0,2}Z/", "/" + anchor + "\\S{0,2}Z/",
		"/[0-9]{1,2}" + anchor + "([aA]|\\x00)Z/", "/" + anchor + "(X|[aA]{0,2})Z/",
		`/[aA][bB][cC][dD][eE][fF][gG][hH][iI][jJ][kK][lL][mM][nN][oO][pP][\x41]{1,1}/`,
	}
	for _, source := range patterns {
		t.Run(source, func(t *testing.T) {
			pattern, ok := wordRoutingPattern(&ast.String{Pattern: &ast.RegexPattern{Value: source}})
			if !ok {
				t.Fatal("declined")
			}
			program, err := wordmatch.CompileRouted([]wordmatch.Rule{{All: []wordmatch.Pattern{pattern}}})
			if err != nil {
				t.Fatal(err)
			}
			scanner := program.NewScanner()
			parsed, err := regex.NewParser(regex.ParserFlagEnableStrictEscapeSequences).Parse(cleanRegexPattern(source))
			if err != nil {
				t.Fatal(err)
			}
			code, err := regex.Compile(parsed)
			if err != nil {
				t.Fatal(err)
			}
			flags := (&RuleCompiler{}).deriveRegexFlags(source, nil) | regex.FlagsScan
			for b := 0; b < 256; b++ {
				for phase := 0; phase < 8; phase++ {
					text := anchor
					if phase%2 != 0 {
						text = strings.ToUpper(text)
					}
					data := append([]byte(strings.Repeat("!", phase)+"12"+text), byte(b), byte(b), 'Z')
					for _, candidate := range [][]byte{data, data[:len(data)-2], []byte(text + "A"), nil} {
						want := regex.Exec(code, candidate, flags)
						got := scanner.Match(candidate)
						if got == wordmatch.Unknown || (got == wordmatch.Match) != want {
							t.Fatalf("input%q: decision%v want%v", candidate, got, want)
						}
					}
				}
			}
		})
	}
}

func TestWordRoutingTextParity(t *testing.T) {
	for _, nocase := range []bool{false, true} {
		literal := "AbCdEfGhIjKlMnOp\x00\xff["
		modifiers := []ast.StringModifier{{Type: ast.StringModifierASCII}}
		suffix := " ascii"
		if nocase {
			modifiers = append(modifiers, ast.StringModifier{Type: ast.StringModifierNocase})
			suffix += " nocase"
		}
		pattern, ok := wordRoutingPattern(&ast.String{Pattern: &ast.TextString{Value: literal}, Modifiers: modifiers})
		if !ok {
			t.Fatal("declined")
		}
		program, err := wordmatch.CompileRouted([]wordmatch.Rule{{All: []wordmatch.Pattern{pattern}}})
		if err != nil {
			t.Fatal(err)
		}
		scanner := program.NewScanner()
		baseline, err := NewCompiler().CompileSource(fmt.Sprintf("rule r {strings:$a=%q%s condition:$a}", literal, suffix))
		if err != nil {
			t.Fatal(err)
		}
		reference := baseline.NewScanner()
		defer reference.Close()
		for _, data := range [][]byte{[]byte(literal), []byte("!" + literal), []byte("ABCDEFGHIJKLMNOP\x00\xff["), []byte("AbCdEfGhIjKlMnOp\x00\xff{"), nil} {
			want, err := reference.Matches(data)
			if err != nil {
				t.Fatal(err)
			}
			got := scanner.Match(data)
			if got == wordmatch.Unknown || (got == wordmatch.Match) != want {
				t.Fatalf("nocase%v input%q: %v want%v", nocase, data, got, want)
			}
		}
	}
}

func FuzzWordRoutingAdapterParity(f *testing.F) {
	program, err := NewCompiler().CompileSource(`
rule structured { strings:
 $a=/(TOKENXYZ12345678|PREFIX9876543210)[0-9]{1,3}[^a-z]{0,2}done/is
 $b="common" condition: all of them }
rule backwards { strings: $a=/[0-9]{1,2}LeftAnchorABCD123.{0,3}END/s condition:$a }
rule folded { strings: $a="CaseFoldMarkerABCD" nocase condition:$a }`)
	if err != nil {
		f.Fatal(err)
	}
	payloads := []string{"TOKENXYZ1234567812!done common", "PREFIX98765432107done common", "TOKENXYZ12345678x!done common", "12LeftAnchorABCD123\nEND", "12LeftAnchorABCD123!!!!END", "casefoldmarkerabcd", "CaseFoldMarkerABC!"}
	f.Add([]byte{})
	f.Add([]byte{0, 255, '\n'})
	for _, payload := range payloads {
		f.Add([]byte(payload))
	}
	for _, size := range []int{1023, 1024, 1025} {
		f.Add(bytes.Repeat([]byte{'!'}, size))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2048 {
			t.Skip()
		}
		routed := program.NewScanner(WithBooleanRouting())
		reference := program.NewScanner()
		defer routed.Close()
		defer reference.Close()
		if routed.booleanRouting == nil {
			t.Fatal("adapter portfolio did not activate routing")
		}
		for _, payload := range payloads {
			injected := make([]byte, 0, len(data)+len(payload))
			middle := len(data) / 2
			injected = append(injected, data[:middle]...)
			injected = append(injected, payload...)
			injected = append(injected, data[middle:]...)
			for _, input := range [][]byte{data, injected} {
				got, err := routed.Matches(input)
				want, wantErr := reference.Matches(input)
				if got != want || fmt.Sprint(err) != fmt.Sprint(wantErr) {
					t.Fatalf("input%q: (%v,%v) != (%v,%v)", input, got, err, want, wantErr)
				}
			}
		}
	})
}

func TestWordRoutingPatternExpansionAllocation(t *testing.T) {
	for _, suffix := range []string{strings.Repeat("x", 4000), strings.Repeat("[xX]", 1000), strings.Repeat("x()", 1000)} {
		source := strings.Repeat("(aa|bb)", 6) + suffix
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		converted, ok := wordRoutingRegex(source, 0)
		runtime.ReadMemStats(&after)
		if !ok || len(converted) != 64 {
			t.Fatalf("expanded alternatives=%d accepted=%v", len(converted), ok)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
			t.Fatalf("bounded conversion allocated%dbytes", allocated)
		}
		runtime.KeepAlive(converted)
	}
}

func wordRoutingPattern(str *ast.String) (wordmatch.Pattern, bool) {
	return newWordRoutingConverter().pattern(str)
}

func wordRoutingRegex(source string, flags regex.Flags) ([]wordmatch.Sequence, bool) {
	return newWordRoutingConverter().regex(source, flags)
}

func TestWordRoutingConversionBudget(t *testing.T) {
	pattern := &ast.String{Pattern: &ast.RegexPattern{Value: `/abcdefghijklmnop(foo|bar)[0-9]{1,3}done/`}}
	probe := newWordRoutingConverter()
	if _, ok := probe.pattern(pattern); !ok {
		t.Fatal("declined representative pattern")
	}
	work, material := wordRoutingWorkLimit-probe.work, wordRoutingMaterialLimit-probe.material
	for _, budget := range []wordRoutingConverter{{work: 2 * work, material: wordRoutingMaterialLimit}, {work: wordRoutingWorkLimit, material: 2 * material}} {
		for i := range 3 {
			if _, ok := budget.pattern(pattern); ok != (i < 2) {
				t.Fatalf("pattern %d accepted=%v, remaining=%+v", i, ok, budget)
			}
		}
		if _, ok := budget.pattern(&ast.String{Pattern: &ast.TextString{Value: "a"}}); ok {
			t.Fatal("exhausted conversion resumed")
		}
	}
	portfolio := newWordRoutingConverter()
	for i := range 2048 {
		if _, ok := portfolio.pattern(pattern); !ok {
			t.Fatalf("ordinary portfolio exhausted at pattern %d", i)
		}
	}
}

func TestWordRoutingLiteralRunAllocations(t *testing.T) {
	node := &regex.Node{Kind: regex.NodeConcat}
	for range 4096 {
		node.Children = append(node.Children, &regex.Node{Kind: regex.NodeLiteral, Value: 'x'})
	}
	allocations := testing.AllocsPerRun(3, func() {
		converted, ok := newWordRoutingConverter().node(node, 0, 0)
		if !ok || len(converted) != 1 || len(converted[0]) != 1 || len(converted[0][0].Literal) != 4096 {
			t.Fatal("literal run was not preserved")
		}
	})
	if allocations > 8 {
		t.Fatalf("literal run allocated %.0f objects", allocations)
	}
}

func TestWordRoutingClassBitmapParity(t *testing.T) {
	for value := range 256 {
		for _, negated := range []bool{false, true} {
			class := &regex.Class{Negated: negated}
			class.Bitmap[value/8] = 1 << (value % 8)
			for _, flags := range []regex.Flags{0, regex.FlagsNoCase} {
				sets, ok := regex.FixedByteSets(&regex.AST{Root: &regex.Node{Kind: regex.NodeClass, Class: class}}, flags)
				if !ok {
					t.Fatal("invalid class")
				}
				converted := wordRoutingClass(class, flags)
				for b := range 256 {
					got := converted.Set[b/64]&(uint64(1)<<(b%64)) != 0
					if got != sets[0].Contains(byte(b)) {
						t.Fatalf("class %02x negated=%v flags=%v byte=%02x", value, negated, flags, b)
					}
				}
			}
		}
	}
}
