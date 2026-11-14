package integration

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/pefixture"
)

func peOverlaySecurityDirOffset(is64 bool) int {
	if is64 {
		return 0x98 + 112 + 4*8
	}
	return 0x98 + 96 + 4*8
}

func peOverlayRvaCountOffset(is64 bool) int {
	if is64 {
		return 0x98 + 108
	}
	return 0x98 + 92
}

func TestLibyaraPEOverlay(t *testing.T) {
	libyaraOracle(t)
	predicates := []string{
		`defined pe.overlay.offset`,
		`defined pe.overlay.size`,
		`pe.overlay.offset == 0`,
		`pe.overlay.size == 0`,
		`pe.overlay.offset == 0x600`,
		`pe.overlay.size == 0x200`,
		`pe.overlay.size == 1`,
		`pe.overlay.offset == 0x700`,
		`pe.overlay.size == 0x100`,
		`pe.overlay.offset == 0x400`,
		`pe.overlay.size == 0x400`,
		`pe.overlay.offset == 0x505`,
		`pe.overlay.size == 0x2fb`,
		`pe.overlay.offset == 0x4000`,
		`pe.overlay.size == 0xc000`,
	}
	source := peProbeSource(predicates)

	for _, is64 := range []bool{false, true} {
		label := "pe32"
		if is64 {
			label = "pe64"
		}
		t.Run(label, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				change func([]byte) []byte
			}{
				{"base", func(d []byte) []byte { return d }},
				{"exact-eof", func(d []byte) []byte { return d[:0x600] }},
				{"one-byte-overlay", func(d []byte) []byte { return d[:0x601] }},
				{"past-eof", func(d []byte) []byte {
					binary.LittleEndian.PutUint32(d[peFixtureSectionOffset(d, 1)+16:], 0x600)
					return d
				}},
				{"u32-overflow", func(d []byte) []byte {
					s1 := peFixtureSectionOffset(d, 1)
					binary.LittleEndian.PutUint32(d[s1+16:], 0x20000)
					binary.LittleEndian.PutUint32(d[s1+20:], 0xffff0000)
					return d
				}},
				{"zero-sections", func(d []byte) []byte {
					binary.LittleEndian.PutUint16(d[0x86:], 0)
					return d
				}},
				{"zero-raw-size", func(d []byte) []byte {
					s1 := peFixtureSectionOffset(d, 1)
					binary.LittleEndian.PutUint32(d[s1+16:], 0)
					binary.LittleEndian.PutUint32(d[s1+20:], 0x700)
					return d
				}},
				{"all-zero-extents", func(d []byte) []byte {
					for i := range 2 {
						s := peFixtureSectionOffset(d, i)
						binary.LittleEndian.PutUint32(d[s+16:], 0)
						binary.LittleEndian.PutUint32(d[s+20:], 0)
					}
					return d
				}},
				{"reversed-sections", func(d []byte) []byte {
					binary.LittleEndian.PutUint32(d[peFixtureSectionOffset(d, 0)+20:], 0x400)
					binary.LittleEndian.PutUint32(d[peFixtureSectionOffset(d, 1)+20:], 0x200)
					return d
				}},
				{"unaligned-raw", func(d []byte) []byte {
					s1 := peFixtureSectionOffset(d, 1)
					binary.LittleEndian.PutUint32(d[s1+16:], 0x100)
					binary.LittleEndian.PutUint32(d[s1+20:], 0x405)
					return d
				}},
				{"cert-exact-overlay", func(d []byte) []byte {
					dir := peOverlaySecurityDirOffset(is64)
					binary.LittleEndian.PutUint32(d[dir:], 0x600)
					binary.LittleEndian.PutUint32(d[dir+4:], 0x200)
					return d
				}},
				{"cert-partial-overlay", func(d []byte) []byte {
					dir := peOverlaySecurityDirOffset(is64)
					binary.LittleEndian.PutUint32(d[dir:], 0x680)
					binary.LittleEndian.PutUint32(d[dir+4:], 0x180)
					return d
				}},
				{"cert-past-eof", func(d []byte) []byte {
					dir := peOverlaySecurityDirOffset(is64)
					binary.LittleEndian.PutUint32(d[dir:], 0x600)
					binary.LittleEndian.PutUint32(d[dir+4:], 0x400)
					return d
				}},
				{"cert-num-dirs-4", func(d []byte) []byte {
					dir := peOverlaySecurityDirOffset(is64)
					binary.LittleEndian.PutUint32(d[dir:], 0x600)
					binary.LittleEndian.PutUint32(d[dir+4:], 0x200)
					binary.LittleEndian.PutUint32(d[peOverlayRvaCountOffset(is64):], 4)
					return d
				}},
				{"sizeof-headers", func(d []byte) []byte {
					binary.LittleEndian.PutUint32(d[0x98+60:], 0x700)
					return d
				}},
				{"section-limit", func([]byte) []byte {
					data := make([]byte, 0x10000)
					copy(data, pefixture.New(is64))
					binary.LittleEndian.PutUint16(data[0x86:], 97)
					start := peFixtureSectionOffset(data, 0)
					for i := 0; i < 97; i++ {
						s := data[start+i*40:]
						copy(s, ".text\x00\x00\x00")
						binary.LittleEndian.PutUint32(s[8:], 0x200)
						binary.LittleEndian.PutUint32(s[12:], uint32(0x1000*(i+1))) //checkednarrow:ignore bounded by 97
						binary.LittleEndian.PutUint32(s[16:], 0x200)
						rawOff := uint32(0x3e00)
						if i == 96 {
							rawOff = 0x4e00
						}
						binary.LittleEndian.PutUint32(s[20:], rawOff)
					}
					return data
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					checkPEPaths(t, source, tc.change(pefixture.New(is64)))
				})
			}
		})
	}

	for name, data := range map[string][]byte{"non_pe": []byte("ordinary"), "empty": nil, "mz_only": []byte("MZ")} {
		t.Run(name, func(t *testing.T) {
			checkPEPaths(t, source, data)
		})
	}
}

func TestLibyaraPEOverlayStrictHeaderCompatibility(t *testing.T) {
	libyaraOracle(t)
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"truncated_sections", func(d []byte) []byte { return d[:0x180] }},
		{"too_many_sections", func(d []byte) []byte { binary.LittleEndian.PutUint16(d[0x86:], 257); return d }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.change(pefixture.New(false))
			const source = `import "pe"
rule recognized { condition: pe.is_pe == 1 and defined pe.overlay.offset and defined pe.overlay.size }
rule rejected { condition: pe.is_pe == 0 and not defined pe.overlay.offset and not defined pe.overlay.size }`
			want, err := scanWithLibyara(t, libyaraOracle(t), source, data)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := want["recognized"]; !ok || len(want) != 1 {
				t.Fatalf("oracle contract changed: %v", want)
			}
			p, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			r, err := p.Scan(data)
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, map[string][]span{"rejected": nil}, r)
		})
	}
}
