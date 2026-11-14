package integration

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/pefixture"
	"github.com/cawalch/go-yara/utils/fs"
)

func TestLibyaraPECalculateChecksum(t *testing.T) {
	libyaraOracle(t)

	// Extract every bit 0..31 so differential comparisons verify exact integer checksum equality.
	var predicates []string
	predicates = append(predicates, `defined pe.calculate_checksum()`, `pe.calculate_checksum() == pe.checksum`)
	for bit := range 32 {
		predicates = append(predicates, fmt.Sprintf("(pe.calculate_checksum() & (1 << %d)) != 0", bit))
	}
	source := peProbeSource(predicates)

	withPattern := func(base []byte, stored uint32, fill byte, extra int) []byte {
		out := make([]byte, len(base)+extra)
		copy(out, base)
		for i := len(base); i < len(out); i++ {
			out[i] = fill
		}
		lfanew := binary.LittleEndian.Uint32(out[0x3c:])
		binary.LittleEndian.PutUint32(out[lfanew+88:], stored)
		return out
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"pe32_zero_stored", withPattern(pefixture.New(false), 0, 0xaa, 0)},
		{"pe32_nonzero_stored", withPattern(pefixture.New(false), 0xdeadbeef, 0xaa, 3)},
		{"pe64_odd1", withPattern(pefixture.New(true), 0x12345678, 0xef, 1)},
		{"pe64_odd2", withPattern(pefixture.New(true), 0, 0xef, 2)},
		{"pe32_carry_64k_plus3", withPattern(pefixture.New(false), 0xffffffff, 0xff, 64*1024+3)},
		{"pe32_unaligned_lfanew", func() []byte {
			out := make([]byte, 0x803)
			base := pefixture.New(false)
			copy(out, base[:0x80])
			copy(out[0x82:], base[0x80:0x1c8])
			binary.LittleEndian.PutUint32(out[0x3c:], 0x82)
			binary.LittleEndian.PutUint32(out[0x82+88:], 0x12345678)
			return out
		}()},
		{"non_pe", []byte("ordinary input data")},
		{"truncated_opt", pefixture.New(false)[:0x90]},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.data) <= 64*1024 {
				checkPEPaths(t, source, tc.data)
				return
			}
			// Above 64 KiB, ScanReader intentionally leaves calculate_checksum undefined (#479/#480);
			// verify buffer and file paths match libyara identically.
			want, err := scanWithLibyara(t, libyaraOracle(t), source, tc.data)
			if err != nil {
				t.Fatal(err)
			}
			prog, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
			if err != nil {
				t.Fatal(err)
			}
			rBuf, err := prog.Scan(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, want, rBuf)
		})
	}

	// Verify real Go toolchain PE executables match libyara checksums bit-for-bit across buffer and mmap files.
	root, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	prog, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	s := prog.NewScanner()
	defer s.Close()
	for _, name := range []string{"gcc-386-mingw-exec", "gcc-amd64-mingw-exec", "gcc-386-mingw-no-symbols-exec"} {
		t.Run("toolchain/"+name, func(t *testing.T) {
			path := filepath.Join(strings.TrimSpace(string(root)), "src", "debug", "pe", "testdata", name)
			data, err := os.ReadFile(path) // #nosec G304 -- standard Go toolchain fixture
			if err != nil {
				t.Fatal(err)
			}
			want, err := scanWithLibyara(t, libyaraOracle(t), source, data)
			if err != nil {
				t.Fatal(err)
			}
			rBuf, err := s.Scan(data)
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, want, rBuf)

			rFile, err := s.ScanFile(path)
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, want, rFile)

			if len(data) >= fs.MinMmapFileSize {
				ctx := t.Context()
				rCtx, err := s.ScanFileWithContext(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				assertReleaseScanResult(t, want, rCtx)
			}
		})
	}
}
