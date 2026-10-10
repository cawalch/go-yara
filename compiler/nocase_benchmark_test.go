package compiler

import (
	"bytes"
	"fmt"
	"testing"
)

func BenchmarkIndexASCIIFoldByte(b *testing.B) {
	for _, size := range []int{16, 64, 256, 1024, 65536} {
		dataClean := bytes.Repeat([]byte("a"), size)
		b.Run(fmt.Sprintf("Clean_%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			want := byte('z')
			b.ResetTimer()
			for b.Loop() {
				if idx := indexASCIIFoldByte(dataClean, want); idx != -1 {
					b.Fatal(idx)
				}
			}
		})
	}
}

func BenchmarkNocaseSinglePattern(b *testing.B) {
	rule := `rule detect_nocase {
		strings:
			$a = "powershell.exe -ExecutionPolicy Bypass" nocase
		condition:
			$a
	}`
	prog, err := NewCompiler().CompileSource(rule)
	if err != nil {
		b.Fatal(err)
	}

	cleanZeros := make([]byte, 65536)
	b.Run("Clean_Zeros_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(cleanZeros)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			matches, err := prog.Matches(cleanZeros)
			if err != nil || matches {
				b.Fatal(err)
			}
		}
	})

	cleanText := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. A wizard's job is to vex chumps quickly in fog. "), 750)[:65536]
	b.Run("Clean_Text_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(cleanText)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			matches, err := prog.Matches(cleanText)
			if err != nil || matches {
				b.Fatal(err)
			}
		}
	})

	hitHead := make([]byte, 65536)
	copy(hitHead, "powershell.exe -executionpolicy bypass")
	b.Run("Hit_Head_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(hitHead)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			matches, err := prog.Matches(hitHead)
			if err != nil || !matches {
				b.Fatal("expected match")
			}
		}
	})

	hitTail := make([]byte, 65536)
	copy(hitTail[65536-45:], "POWERSHELL.EXE -ExecutionPolicy Bypass")
	b.Run("Hit_Tail_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(hitTail)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			matches, err := prog.Matches(hitTail)
			if err != nil || !matches {
				b.Fatal("expected match")
			}
		}
	})
}

func BenchmarkNocaseMultiPattern(b *testing.B) {
	rule := `rule detect_multi_nocase {
		strings:
			$s1 = "cmd.exe" nocase
			$s2 = "vssadmin delete shadows /all /quiet" nocase
			$s3 = "wbadmin delete catalog -quiet" nocase
		condition:
			any of them
	}`
	prog, err := NewCompiler().CompileSource(rule)
	if err != nil {
		b.Fatal(err)
	}
	clean := make([]byte, 65536)
	b.Run("Clean_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(clean)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			matches, err := prog.Matches(clean)
			if err != nil || matches {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkNocaseModifiers(b *testing.B) {
	ruleWide := `rule r_wide { strings: $w = "SeDebugPrivilege" wide nocase condition: $w }`
	progWide, err := NewCompiler().CompileSource(ruleWide)
	if err != nil {
		b.Fatal(err)
	}
	clean := make([]byte, 65536)
	b.Run("Wide_Nocase_Clean_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(clean)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			matches, err := progWide.Matches(clean)
			if err != nil || matches {
				b.Fatal(err)
			}
		}
	})

	ruleOneByte := `rule r_one { strings: $b = "Z" nocase condition: $b }`
	progOneByte, err := NewCompiler().CompileSource(ruleOneByte)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("OneByte_Nocase_Clean_64KB", func(b *testing.B) {
		b.SetBytes(int64(len(clean)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			matches, err := progOneByte.Matches(clean)
			if err != nil || matches {
				b.Fatal(err)
			}
		}
	})
}
