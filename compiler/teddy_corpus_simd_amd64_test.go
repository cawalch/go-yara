//go:build go1.27 && goexperiment.simd && amd64

package compiler

import (
	"bytes"
	"simd"
	"simd/archsimd"
	"strconv"
	"testing"

	"github.com/cawalch/go-yara/regex"
)

func TestTeddyAVX2Corpus(t *testing.T) {
	available := archsimd.X86.AVX2() && byteSIMDHardwareAvailable(simd.BroadcastUint8s(0))
	for _, groups := range []int{1, 8, 9, 16, 64, 65} {
		t.Run(strconv.Itoa(groups), func(t *testing.T) {
			patterns := make([]acStringInfo, 128)
			for i := range patterns {
				patterns[i] = acStringInfo{Data: []byte{0x80 + byte(i%groups), 'A', 'z', byte(i)}, Flags: regex.FlagsNoCase}
			}
			filter := newTeddyPrefilter(patterns)
			if !available || groups > maxTeddyPatterns {
				if filter != nil {
					t.Fatal("ineligible corpus enabled SIMD")
				}
				return
			}
			gate, ok := filter.(*corpusTeddyPrefilter)
			if !ok {
				t.Fatalf("missing AVX2 corpus gate: %T", filter)
			}
			for _, size := range []int{0, 1, 2, 3, 31, 32, 33, 34, 63, 64, 65, 255, 256, 257, 258, 287, 288, 289} {
				data := bytes.Repeat([]byte{'x'}, size)
				if gate.mayMatch(data, nil) {
					t.Fatalf("clean input not rejected, size=%d", size)
				}
				for i := range groups {
					for pos := 0; pos+3 <= size; pos++ {
						copy(data[pos:], []byte{0x80 + byte(i), 'a', 'Z'})
						if !gate.mayMatch(data, nil) {
							t.Fatalf("lost prefix %d at %d of %d", i, pos, size)
						}
						copy(data[pos:], "xxx")
					}
				}
			}
		})
	}
}

func TestTeddyAVX2CorpusInstallation(t *testing.T) {
	available := archsimd.X86.AVX2() && byteSIMDHardwareAvailable(simd.BroadcastUint8s(0))
	for _, short := range []int{0, 1, 2} {
		ac := corpusTeddyAutomaton(t, short)
		if (ac.teddyGate != nil) != available {
			t.Fatalf("corpus gate installation: short=%d hardware=%t", short, available)
		}
	}
	p := mustCompileStreamingProgram(t, teddyCorpusSource(128))
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalCompiledProgram(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if (restored.sharedAutomaton.teddyGate != nil) != available {
		t.Fatal("reload did not rebuild corpus gate")
	}
}
