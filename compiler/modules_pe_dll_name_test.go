package compiler

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEDLLName(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule absent {condition: not defined pe.dll_name}
rule empty {condition: defined pe.dll_name and pe.dll_name == ""}
rule named {condition: pe.dll_name == "Example.DLL" and pe.dll_name != "example.dll"}
rule raw {condition: pe.dll_name == "\xffName"}
rule long {condition: pe.dll_name == "` + strings.Repeat("N", 513) + `"}`)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		s := p.NewScanner()
		for _, is64 := range []bool{false, true} {
			for _, count := range []int{0, 3} {
				for _, tc := range []struct {
					name, want string
					change     func([]byte)
				}{
					{"named", "named", func([]byte) {}},
					{"absent", "absent", func(d []byte) { binary.LittleEndian.PutUint32(d[0x80c:], 0) }},
					{"empty", "empty", func(d []byte) { d[0x428] = 0 }},
					{"raw", "raw", func(d []byte) { copy(d[0x428:], "\xffName\x00") }},
					{"long", "long", func(d []byte) {
						off := len(d) - 600
						copy(d[off:], strings.Repeat("N", 513)+"\x00")
						binary.LittleEndian.PutUint32(d[0x80c:], uint32(off+0x1c00)) //checkednarrow:ignore bounded fixture offset
					}},
					{"unmapped", "absent", func(d []byte) { binary.LittleEndian.PutUint32(d[0x80c:], 0xffffffff) }},
					{"unterminated", "absent", func(d []byte) {
						d[len(d)-1] = 'X'
						binary.LittleEndian.PutUint32(d[0x80c:], uint32(len(d)-1+0x1c00)) //checkednarrow:ignore bounded fixture offset
					}},
				} {
					data := pefixture.Exports(is64, count)
					tc.change(data)
					for _, scan := range []struct {
						data []byte
						want string
					}{{data, tc.want}, {nil, "absent"}, {pefixture.New(is64), "absent"}, {data, tc.want}} {
						input, want := scan.data, scan.want
						r, err := s.Scan(input)
						if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[want] {
							t.Fatalf("%s PE64=%t count=%d want=%s: %v %v", tc.name, is64, count, want, r, err)
						}
					}
				}
			}
		}
		s.Close()
		for _, tc := range []struct {
			data any
			want string
		}{
			{nil, "absent"}, {map[string]any{}, "absent"},
			{map[string]any{"dll_name": ""}, "empty"},
			{map[string]any{"dll_name": "Example.DLL"}, "named"},
		} {
			s := p.NewScanner(WithModuleData("pe", tc.data))
			r, err := s.Scan(pefixture.Exports(false, 3))
			if err != nil || len(r.MatchedRules) != 1 || !r.RuleResults[tc.want] || s.moduleCache.pe != nil {
				t.Fatalf("host want=%s: %v %v", tc.want, r, err)
			}
			s.Close()
		}
		blob, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		p, err = UnmarshalCompiledProgram(blob)
		if err != nil {
			t.Fatal(err)
		}
	}
}
