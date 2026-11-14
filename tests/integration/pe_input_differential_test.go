package integration

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/pefixture"
	"github.com/cawalch/go-yara/utils/fs"
)

type diffChunkReader struct {
	data []byte
	size int
}

func (r *diffChunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), len(r.data), r.size)
	copy(p[:n], r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestLibyaraPEInputAvailabilityParity(t *testing.T) {
	libyaraOracle(t)

	// Prefix rules check metadata within the 64 KiB prefix and full-stream overlay extents.
	prefixSource := peProbeSource([]string{
		`pe.is_pe == 1`,
		`pe.number_of_sections == 2`,
		`pe.imports("Example.DLL") == 3`,
		`pe.imphash() == "52ee6f8c06f82c1a4906c4287b38a731"`,
		`pe.overlay.size == 512`,
	})
	// Full-image rules add exports that cross the 64 KiB boundary in mid/large fixtures.
	fullSource := peProbeSource([]string{
		`pe.is_pe == 1`,
		`pe.imports("Example.DLL") == 3`,
		`pe.number_of_exports >= 3`,
		`pe.exports("Function00000")`,
		`pe.dll_name == "Example.DLL"`,
		`pe.overlay.size == 512`,
	})

	withOverlay := func(base []byte, extra int) []byte {
		out := make([]byte, len(base)+extra)
		copy(out, base)
		return out
	}

	smallPE := withOverlay(pefixture.Exports(false, 3), 512)
	midPE := withOverlay(pefixture.Exports(false, 3500), 512)
	largePE := withOverlay(pefixture.Exports(false, 5200), 512)
	if len(smallPE) >= 64*1024 || len(midPE) <= 64*1024 || len(midPE) >= fs.MinMmapFileSize || len(largePE) < fs.MinMmapFileSize {
		t.Fatalf("unexpected fixture sizes: small=%d mid=%d large=%d", len(smallPE), len(midPE), len(largePE))
	}

	// Small <= 64 KiB: every scan path (including readers and short reads) matches libyara completely.
	checkPEPaths(t, fullSource, smallPE)

	// Mid (64 KiB < size < 128 KiB) & Large (>= 128 KiB): complete buffer and file scans match libyara on full metadata.
	for name, data := range map[string][]byte{"mid": midPE, "large": largePE} {
		t.Run(name, func(t *testing.T) {
			checkPEPaths(t, prefixSource, data)

			want, err := scanWithLibyara(t, libyaraOracle(t), fullSource, data)
			if err != nil {
				t.Fatal(err)
			}
			prog, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), fullSource)
			if err != nil {
				t.Fatal(err)
			}
			s := prog.NewScanner()
			defer s.Close()

			path := filepath.Join(t.TempDir(), name+".exe")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			rFile, err := s.ScanFile(path)
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, want, rFile)

			cancelCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var rCancel *compiler.ScanResult
			if len(data) >= fs.MinMmapFileSize {
				rCancel, err = s.ScanFileWithContext(cancelCtx, path)
			} else {
				// Below MinMmapFileSize, callers wanting full metadata + cancellation pass bytes to ScanWithContext.
				var scanInput []byte
				scanInput, err = os.ReadFile(path) // #nosec G304 -- test temp file created above
				if err != nil {
					t.Fatal(err)
				}
				rCancel, err = s.ScanWithContext(cancelCtx, scanInput)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertReleaseScanResult(t, want, rCancel)

			// Verify OneByteReader and small chunks match libyara on prefix metadata + full overlay.
			wantPrefix, err := scanWithLibyara(t, libyaraOracle(t), prefixSource, data)
			if err != nil {
				t.Fatal(err)
			}
			prefixProg, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), prefixSource)
			if err != nil {
				t.Fatal(err)
			}
			ps := prefixProg.NewScanner()
			defer ps.Close()
			for rname, rd := range map[string]io.Reader{
				"onebyte": iotest.OneByteReader(bytes.NewReader(data)),
				"chunk13": &diffChunkReader{data: data, size: 13},
			} {
				rr, err := ps.ScanReader(rd)
				if err != nil {
					t.Fatalf("%s: %v", rname, err)
				}
				assertReleaseScanResult(t, wantPrefix, rr)
			}
		})
	}
}
