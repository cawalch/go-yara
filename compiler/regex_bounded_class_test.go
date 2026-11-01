package compiler

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestBoundedClassCounter(t *testing.T) {
	for _, values := range [][]byte{[]byte("0123456789abcdef"), []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"), {0, 127, 128, 255}, {}} {
		class := newBoundedClassSet(regex.NewByteSet(values))
		for b := range 256 {
			for pos := range 96 {
				data := bytes.Repeat([]byte{0}, 96)
				if len(values) > 0 {
					data = bytes.Repeat(values[:1], 96)
				}
				data[pos] = byte(b)
				if got, want := countBoundedClass(data, &class), countBoundedClassScalar(data, &class); got != want {
					t.Fatalf("byte=%d pos=%d: got %d want %d", b, pos, got, want)
				}
			}
		}
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		var values, data []byte
		for b := range 256 {
			if rng.IntN(2) == 0 {
				values = append(values, byte(b))
			}
		}
		class := newBoundedClassSet(regex.NewByteSet(values))
		for range rng.IntN(160) {
			data = append(data, values[rng.IntN(len(values))])
		}
		data = append(data, byte(rng.IntN(256)))
		if countBoundedClass(data, &class) != countBoundedClassScalar(data, &class) {
			t.Fatal("arbitrary bitmap mismatch")
		}
	}
}

func TestBoundedClassEligibility(t *testing.T) {
	for _, tc := range []struct {
		expression string
		want       bool
	}{
		{`key=[a-z]{16,64}`, true}, {`[a-z]{16}`, true}, {`[a-z]{16,64}?`, true}, {`key=\d{32,64}`, true},
		{`key=[a-z]{15,64}`, false}, {`key=[a-z]+`, false}, {`key=[a-z]{32,}`, false},
		{`key=[a-z]{32,64}END`, false}, {`^key=[a-z]{32,64}`, false}, {`key=[a-z]{32,64}$`, false},
		{`(key|token)=[a-z]{32,64}`, false}, {`key=([a-z]{16,32})+`, false}, {`[a-z]{16,32}[0-9]{16}`, false},
	} {
		p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule r {strings:$a=/%s/ condition:$a}`, tc.expression))
		if got := p.Rules[0].RegexPatterns["$a"].boundedClass != nil; got != tc.want {
			t.Errorf("%s: eligible=%t", tc.expression, got)
		}
	}
	for n := range 80 {
		if compileBoundedClass(bytes.Repeat([]byte{regex.OpClass}, n), 0) != nil {
			t.Fatal("accepted incomplete bytecode")
		}
	}
	for _, n := range []int{4096, 4097} {
		code := append(bytes.Repeat([]byte{regex.OpDigit}, n), regex.OpMatch)
		if (compileBoundedClass(code, 0) != nil) != (n == 4096) {
			t.Fatal("wrong bounded-plan size limit")
		}
	}
}

func TestBoundedClassVMParity(t *testing.T) {
	for _, cls := range []string{`[a-z]`, `[^a-z]`, `[\x00\x80-\xff]`, `\d`, `\D`, `\w`, `\W`, `\s`, `\S`} {
		for _, suffix := range []string{`{16}`, `{16,64}`, `{16,64}?`} {
			for _, modifier := range []string{"", "nocase"} {
				p := mustCompileStreamingProgram(t, fmt.Sprintf(`rule r {strings:$a=/key=%s%s/ %s condition:$a}`, cls, suffix, modifier))
				pattern := p.Rules[0].RegexPatterns["$a"]
				if pattern.boundedClass == nil {
					t.Fatal("missing plan")
				}
				for _, b := range []byte{0, 'a', 'A', '0', '_', ' ', '\n', 128, 255} {
					for _, n := range []int{0, 15, 16, 17, 31, 32, 33, 63, 64, 65} {
						data := append([]byte("key="), bytes.Repeat([]byte{b}, n)...)
						got, gs, ge := execRegexMatchAt(nil, pattern, data, pattern.Flags, false, 0, nil)
						want, ws, we := regex.ExecMatchBatch(nil, pattern.Code, data, pattern.Flags, 0)
						if got != want || got && (gs != ws || ge != we) {
							t.Fatalf("%s%s %s byte=%d n=%d: %t/%d/%d != %t/%d/%d", cls, suffix, modifier, b, n, got, gs, ge, want, ws, we)
						}
					}
				}
			}
		}
	}
}

func TestBoundedClassReloadAndFallback(t *testing.T) {
	captured := mustCompileStreamingProgram(t, `rule r {strings:$a=/key=([a-z]{32,64})/ capture(value=1) condition:$a}`)
	if captured.Rules[0].RegexPatterns["$a"].boundedClass != nil {
		t.Fatal("capture replay must retain its verifier")
	}
	p := mustCompileStreamingProgram(t, `rule r {strings:$a=/key=[a-z]{32,64}/ nocase ascii wide fullword condition:#a>0}`)
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range []*CompiledProgram{p, restored} {
		if program.Rules[0].RegexPatterns["$a"].boundedClass == nil {
			t.Fatal("plan missing after reload")
		}
		s := program.NewScanner(WithMatchData(128))
		defer s.Close()
		for _, data := range [][]byte{[]byte("!key=" + strings.Repeat("a", 40) + "!"), widenRegexPrefix([]byte("!key=" + strings.Repeat("A", 40) + "!")), nil} {
			got, err := s.Scan(data)
			if err != nil {
				t.Fatal(err)
			}
			streamed, err := s.ScanReader(bytes.NewReader(data))
			if err != nil || !reflect.DeepEqual(got.Matches, streamed.Matches) {
				t.Fatalf("stream parity: %v", err)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := s.ScanWithContext(ctx, []byte("key="+strings.Repeat("a", 64))); err == nil {
			t.Fatal("cancellation ignored")
		}
	}
}

func TestBoundedClassRuntimeFlags(t *testing.T) {
	p := mustCompileStreamingProgram(t, `rule r {strings:$a=/key=[a-z]{16,64}/ condition:$a}`)
	pattern := p.Rules[0].RegexPatterns["$a"]
	old := pattern
	old.boundedClass = nil
	for _, flags := range []regex.Flags{0, regex.FlagsGreedy, regex.FlagsGreedy | regex.FlagsFullwordEnd, regex.FlagsGreedy | regex.FlagsExhaustive, regex.FlagsGreedy | regex.FlagsNoCase, regex.FlagsWide | regex.FlagsGreedy} {
		for _, data := range [][]byte{[]byte("key=" + strings.Repeat("a", 40)), []byte("KEY=" + strings.Repeat("A", 40)), widenRegexPrefix([]byte("key=" + strings.Repeat("a", 40)))} {
			wide := flags&regex.FlagsWide != 0
			got, gs, ge := execRegexMatchAt(nil, pattern, data, flags, wide, 0, nil)
			want, ws, we := execRegexMatchAt(nil, old, data, flags, wide, 0, nil)
			if got != want || got && (gs != ws || ge != we) {
				t.Fatal("runtime flags changed match selection")
			}
		}
	}
}

func FuzzBoundedClass(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), []byte(strings.Repeat("a", 64)))
	f.Add([]byte{0, 127, 128, 255}, []byte{255, 128, 0})
	f.Fuzz(func(t *testing.T, values, data []byte) {
		values = values[:min(len(values), 256)]
		if len(data) > 4096 {
			data = data[:4096]
		}
		class := newBoundedClassSet(regex.NewByteSet(values))
		if countBoundedClass(data, &class) != countBoundedClassScalar(data, &class) {
			t.Fatal("SIMD/scalar mismatch")
		}
	})
}

func FuzzBoundedClassVM(f *testing.F) {
	f.Add([]byte("end"), byte('a'), byte(64))
	f.Add([]byte("key="), byte(255), byte(32))
	p := mustCompileStreamingProgram(f, `
rule greedy {strings:$a=/key=[a-z]{16,64}/ nocase condition:$a}
rule lazy {strings:$a=/key=[a-z]{16,64}?/ condition:$a}
rule negative {strings:$a=/key=[^a-z]{16,64}/ nocase condition:$a}
rule bare {strings:$a=/[a-z]{16,64}?/ condition:$a}`)
	f.Fuzz(func(t *testing.T, data []byte, value, size byte) {
		input := append([]byte("key="), bytes.Repeat([]byte{value}, int(size)%96)...)
		input = append(input, data[:min(len(data), 256)]...)
		for _, rule := range p.Rules {
			pattern := rule.RegexPatterns["$a"]
			old := pattern
			old.boundedClass = nil
			for _, start := range []int{-1, 0, 4, len(input), len(input) + 1} {
				got, gs, ge := execRegexMatchAt(nil, pattern, input, pattern.Flags, false, start, nil)
				want, ws, we := execRegexMatchAt(nil, old, input, old.Flags, false, start, nil)
				if got != want || got && (gs != ws || ge != we) {
					t.Fatal("bounded plan/VM mismatch")
				}
			}
		}
	})
}

func TestBoundedClassPublicParity(t *testing.T) {
	p := mustCompileStreamingProgram(t, boundedClassSource(40, false))
	for _, n := range []int{0, 15, 16, 31, 32, 33, 64, 65, 128} {
		data := []byte("!key=" + strings.Repeat("a", n) + "!key=" + strings.Repeat("z", 32))
		result, err := p.Scan(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range p.Rules {
			linear := buildLinearRegexContext(rule, data)
			want := matchRangesInOrder(linear.Matches["$a"])
			linear.Release()
			if got := matchRangesInOrder(result.Matches[rule.Name]["$a"]); !slices.Equal(got, want) {
				t.Fatal("shared candidate/VM mismatch")
			}
		}
	}
}
