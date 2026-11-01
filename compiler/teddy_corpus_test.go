package compiler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestTeddyPrefixCover(t *testing.T) {
	folded := []acStringInfo{
		{Data: []byte("AbC_first"), Flags: regex.FlagsNoCase},
		{Data: []byte("aBc_second"), Flags: regex.FlagsNoCase},
		{Data: []byte("AbC_exact")},
	}
	cover := teddyPrefixCover(folded)
	if len(cover) != 2 || string(cover[0].Data) != "AbC" || cover[0].Flags&regex.FlagsNoCase == 0 || cover[1].Flags&regex.FlagsNoCase != 0 {
		t.Fatalf("wrong case cover: %+v", cover)
	}
	if string(folded[0].Data) != "AbC_first" {
		t.Fatal("cover changed source patterns")
	}
	many := make([]acStringInfo, 0, maxTeddyPatterns+3)
	for i := range maxTeddyPatterns + 1 {
		many = append(many, acStringInfo{Data: []byte{'a', byte(i), 0xff}})
	}
	if got := teddyPrefixCover(many); got != nil {
		t.Fatal("accepted an incomplete prefix cover")
	}
	// A short pattern at the end reduces every prefix's width. Determine that
	// width before rejecting a corpus with too many longer prefixes.
	many = append(many, acStringInfo{Data: []byte("a")})
	if got := teddyPrefixCover(many); len(got) != 1 || string(got[0].Data) != "a" {
		t.Fatalf("short pattern lost: %+v", got)
	}
	many = append(many, acStringInfo{})
	if got := teddyPrefixCover(many); got != nil {
		t.Fatal("empty pattern must disable skipping")
	}
	if got := newTeddyPrefilter([]acStringInfo{{Data: []byte("abc")}, {}}); got != nil {
		t.Fatal("empty pattern enabled SIMD")
	}
	if got := teddyPrefixCover(nil); len(got) != 0 {
		t.Fatal("nonempty cover for no patterns")
	}
}

func corpusTeddyAutomaton(t testing.TB, short int) *acAutomaton {
	t.Helper()
	ac := newacAutomaton()
	for i := range 80 {
		flags := regex.Flags(0)
		prefix := "api"
		if i%2 == 1 {
			prefix = "SeC"
			flags = regex.FlagsNoCase
		}
		data := []byte(fmt.Sprintf("%s_token_%02d", prefix, i))
		if err := ac.AddStringWithFlags(fmt.Sprintf("$p%d", i), data, false, false, flags); err != nil {
			t.Fatal(err)
		}
	}
	if short > 0 {
		if err := ac.AddString("$short", []byte("api")[:short], false, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	return ac
}

func TestTeddyCorpusScanPaths(t *testing.T) {
	for _, short := range []int{0, 1, 2} {
		ac := corpusTeddyAutomaton(t, short)
		if TeddySIMDSupported() && runtime.GOARCH == "arm64" && ac.teddyGate == nil {
			t.Fatal("large corpus did not enable NEON filter")
		}
		scalar := ac.Clone()
		if scalar.teddyGate != ac.teddyGate {
			t.Fatal("Clone dropped the corpus gate")
		}
		scalar.teddy = nil
		scalar.teddyGate = nil
		for _, wideState := range []bool{false, true} {
			active := ac.Clone()
			reference := scalar.Clone()
			if wideState {
				for _, machine := range []*acAutomaton{active, reference} {
					machine.transitions16 = nil
					machine.transitions32 = make([][256]int32, len(machine.states))
					for i, state := range machine.states {
						machine.transitions32[i] = state.transitions
					}
				}
			}
			for _, offset := range []int{0, 1, 15, 16, 17, 31, 32, 63, 64, 127, 255, 256, 495, 496, 497, 500, 511} {
				data := bytes.Repeat([]byte("x"), 512)
				copy(data[offset:], "sEc_token_79")
				want := slices.Collect(reference.SearchIter(data))
				got := slices.Collect(active.SearchIter(data))
				if !slices.Equal(got, want) {
					t.Fatalf("short=%d wideState=%t offset=%d: %v != %v", short, wideState, offset, got, want)
				}
				if got := collectSearchWithCancel(t, active, data); !slices.Equal(got, want) {
					t.Fatalf("cancelable mismatch at %d", offset)
				}
				if offset+len("sEc_token_79") <= len(data) && len(want) != 1 {
					t.Fatalf("missing planted match at %d", offset)
				}
			}
		}
	}
}

func TestTeddyCorpusScannerReloadAndReuse(t *testing.T) {
	p := mustCompileStreamingProgram(t, teddyCorpusSource(128))
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, program := range []*CompiledProgram{p, restored} {
		if TeddySIMDSupported() && runtime.GOARCH == "arm64" && program.sharedAutomaton.teddyGate == nil {
			t.Fatal("compiled/loaded shared filter absent")
		}
		scalar := *program
		ac := program.sharedAutomaton.Clone()
		ac.teddy = nil
		ac.teddyGate = nil
		scalar.sharedAutomaton = ac
		scanner := program.NewScanner(WithMatchData(64))
		defer scanner.Close()
		reference := scalar.NewScanner(WithMatchData(64))
		defer reference.Close()
		clean := bytes.Repeat([]byte("request completed status=200 normal activity "), 64)
		positive := bytes.Clone(clean)
		copy(positive[513:], "tok_token_00003")
		for _, data := range [][]byte{clean, positive, nil, positive, clean} {
			got, err := scanner.Scan(data)
			if err != nil {
				t.Fatal(err)
			}
			want, err := reference.Scan(data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("public scan results differ")
			}
			streamed, err := scanner.ScanReader(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Matches, streamed.Matches) {
				t.Fatal("reader matches differ")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := scanner.ScanWithContext(ctx, positive); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error=%v", err)
		}
	}
}

func FuzzTeddyCorpus(f *testing.F) {
	f.Add([]byte("api_token_00"), uint16(0))
	f.Add(bytes.Repeat([]byte("SeC_token_79 "), 40), uint16(255))
	ac := corpusTeddyAutomaton(f, 0)
	if ac.teddyGate == nil {
		f.Skip("requires the ARM64 SIMD corpus gate")
	}
	scalar := ac.Clone()
	scalar.teddy = nil
	scalar.teddyGate = nil
	f.Fuzz(func(t *testing.T, data []byte, offset uint16) {
		if len(data) > 4096 {
			data = data[:4096]
		}
		input := make([]byte, 512+len(data))
		copy(input, data)
		copy(input[int(offset)%len(input):], "SEC_token_79")
		got := slices.Collect(ac.SearchIter(input))
		want := slices.Collect(scalar.SearchIter(input))
		if !slices.Equal(got, want) {
			t.Fatal("SIMD/scalar mismatch")
		}
	})
}

func TestTeddyCorpusTailAndCheckpoints(t *testing.T) {
	for _, short := range []int{0, 1, 2} {
		ac := corpusTeddyAutomaton(t, short)
		scalar := ac.Clone()
		scalar.teddy = nil
		scalar.teddyGate = nil
		for _, offset := range []int{65533, 65534, 65535, 65536, 65537, 131071, 131072, 131103} {
			data := make([]byte, 131104)
			token := []byte("api_token_78")
			if short > 0 {
				token = token[:short]
			}
			copy(data[offset:], token)
			want := slices.Collect(scalar.SearchIter(data))
			if got := slices.Collect(ac.SearchIter(data)); !slices.Equal(got, want) {
				t.Fatalf("tail mismatch short=%d offset=%d", short, offset)
			}
			// A non-nil open channel forces the bounded cancellation-window path.
			done := make(chan struct{})
			var got []acMatch
			ac.SearchWithCancel(data, done, func(m acMatch) bool { got = append(got, m); return true })
			if !slices.Equal(got, want) {
				t.Fatalf("checkpoint mismatch short=%d offset=%d", short, offset)
			}
			if offset+len(token) <= len(data) && len(want) != 1 {
				t.Fatal("planted token missing")
			}
		}
	}
}

func TestTeddyCorpusWideBinaryAndReset(t *testing.T) {
	ac := newacAutomaton()
	for i := range 80 {
		data := widenRegexPrefix([]byte(fmt.Sprintf("wide_%02d", i)))
		if err := ac.AddStringWithFlags(fmt.Sprintf("$w%d", i), data, false, false, regex.FlagsNoCase); err != nil {
			t.Fatal(err)
		}
	}
	binary := []byte{0xff, 0x80, 0, 0xfe}
	if err := ac.AddString("$binary", binary, false, false); err != nil {
		t.Fatal(err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	scalar := ac.Clone()
	scalar.teddy = nil
	scalar.teddyGate = nil
	for _, token := range [][]byte{binary, widenRegexPrefix([]byte("WiDe_79"))} {
		for i := range 40 {
			data := bytes.Repeat([]byte{'x'}, 256+i)
			copy(data[len(data)-len(token):], token)
			want := slices.Collect(scalar.SearchIter(data))
			if len(want) != 1 {
				t.Fatal("missing planted tail token")
			}
			if got := slices.Collect(ac.SearchIter(data)); !slices.Equal(got, want) {
				t.Fatalf("binary/wide tail mismatch at length %d", len(data))
			}
		}
	}
	ac.Reset()
	if ac.teddyGate != nil {
		t.Fatal("Reset retained corpus gate")
	}
	if err := ac.AddString("$new", []byte("new"), false, false); err != nil {
		t.Fatal(err)
	}
	if err := ac.Compile(); err != nil {
		t.Fatal(err)
	}
	if got := slices.Collect(ac.SearchIter([]byte("new"))); len(got) != 1 {
		t.Fatal("Reset/recompile lost new match")
	}
}

func TestTeddyCorpusTailBanks(t *testing.T) {
	for _, groups := range []int{8, 9, 16, 64, 65} {
		ac := newacAutomaton()
		for i := range 128 {
			g := byte(i % groups)
			if err := ac.AddString(fmt.Sprintf("$p%d", i), []byte{0x80 + g, 0x40 + g, 0x7f, byte(i)}, false, false); err != nil {
				t.Fatal(err)
			}
		}
		if err := ac.Compile(); err != nil {
			t.Fatal(err)
		}
		if TeddySIMDSupported() && runtime.GOARCH == "arm64" && (ac.teddyGate != nil) != (groups <= maxTeddyPatterns) {
			t.Fatalf("wrong gate eligibility for %d prefixes", groups)
		}
		scalar := ac.Clone()
		scalar.teddy = nil
		scalar.teddyGate = nil
		for extra := range 40 {
			data := bytes.Repeat([]byte{'x'}, 256+extra)
			copy(data[len(data)-4:], ac.strings[127].Data)
			want := slices.Collect(scalar.SearchIter(data))
			if len(want) != 1 {
				t.Fatal("missing planted bank tail")
			}
			if got := slices.Collect(ac.SearchIter(data)); !slices.Equal(got, want) {
				t.Fatalf("bank/tail mismatch for %d groups, length %d", groups, len(data))
			}
		}
	}
}

func TestTeddyCorpusRejectAllocations(t *testing.T) {
	p := mustCompileStreamingProgram(t, teddyCorpusSource(128))
	s := p.NewScanner()
	defer s.Close()
	data := bytes.Repeat([]byte("request completed status=200 normal activity "), 24)
	scan := func() {
		matched, err := s.Matches(data)
		if err != nil || matched {
			t.Fatalf("clean scan: matched=%v err=%v", matched, err)
		}
	}
	scan()
	if allocations := testing.AllocsPerRun(100, scan); allocations != 0 {
		t.Fatalf("clean corpus rejection allocated %g times", allocations)
	}
}
