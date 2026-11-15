package integration

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func yaraHexEscape(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b) * 4)
	for _, v := range b {
		fmt.Fprintf(&sb, "\\x%02x", v)
	}
	return sb.String()
}

func TestPERichSignatureDifferential(t *testing.T) {
	libyaraOracle(t)

	entries := []pefixture.RichEntry{
		{ToolID: 259, Version: 29500, Count: 12},
		{ToolID: 257, Version: 29500, Count: 3},
		{ToolID: 259, Version: 29500, Count: 5},
		{ToolID: 260, Version: 31000, Count: 0xffffffff},
		{ToolID: 260, Version: 31000, Count: 2},
	}

	buildRichExpectations := func(data []byte, key uint32) []string {
		rawLen := 16 + len(entries)*8
		clearBuf := make([]byte, rawLen)
		for off := 0; off < rawLen; off += 4 {
			w := binary.LittleEndian.Uint32(data[0x80+off : 0x80+off+4])
			binary.LittleEndian.PutUint32(clearBuf[off:off+4], w^key)
		}
		versionBuf := make([]byte, len(entries)*4)
		for i := range entries {
			copy(versionBuf[i*4:i*4+4], clearBuf[16+i*8:16+i*8+4])
		}
		return []string{
			`pe.is_pe == 1`,
			`defined pe.rich_signature.offset`,
			`pe.rich_signature.offset == 128`,
			fmt.Sprintf(`pe.rich_signature.length == %d`, rawLen),
			fmt.Sprintf(`pe.rich_signature.key == 0x%x`, key),
			fmt.Sprintf(`pe.rich_signature.raw_data == "%s"`, yaraHexEscape(data[0x80:0x80+rawLen])),
			fmt.Sprintf(`pe.rich_signature.clear_data == "%s"`, yaraHexEscape(clearBuf)),
			fmt.Sprintf(`pe.rich_signature.version_data == "%s"`, yaraHexEscape(versionBuf)),
			`pe.rich_signature.version(29500) == 20`,
			`pe.rich_signature.version(29500, 259) == 17`,
			`pe.rich_signature.version(29500, 257) == 3`,
			`pe.rich_signature.version(31000, 260) == 0x100000001`,
			`pe.rich_signature.toolid(259) == 17`,
			`pe.rich_signature.toolid(259, 29500) == 17`,
			`pe.rich_signature.toolid(257, 29500) == 3`,
			`pe.rich_signature.toolid(260) == 0x100000001`,
			`pe.rich_signature.version(999) == 0`,
			`pe.rich_signature.toolid(999, 29500) == 0`,
			`pe.rich_signature.version(-1) == 0`,
			`pe.rich_signature.version(0x10000) == 0`,
			`pe.rich_signature.version(29500, -1) == 0`,
			`pe.rich_signature.toolid(-1) == 0`,
			`pe.rich_signature.toolid(0x10000) == 0`,
			`pe.rich_signature.toolid(259, 0x10000) == 0`,
			`defined pe.rich_signature.version(999)`,
			`defined pe.rich_signature.toolid(999)`,
			`defined pe.rich_signature.version(-1)`,
			`defined pe.rich_signature.toolid(0x10000)`,
		}
	}

	rich32 := pefixture.RichPE(false, pefixture.RichOptions{Key: 0x4a3b2c1d, TailZeroWords: 2, Entries: entries})
	rich64 := pefixture.RichPE(true, pefixture.RichOptions{Key: 0x4a3b2c1d, Entries: entries})
	zeroRich := pefixture.RichPE(false, pefixture.RichOptions{Key: 0x01020304})

	for _, tc := range []struct {
		name       string
		data       []byte
		predicates []string
	}{
		{name: "pe32_rich", data: rich32, predicates: buildRichExpectations(rich32, 0x4a3b2c1d)},
		{name: "pe64_rich", data: rich64, predicates: buildRichExpectations(rich64, 0x4a3b2c1d)},
		{
			name: "zero_entries_rich",
			data: zeroRich,
			predicates: []string{
				`pe.is_pe == 1`,
				`pe.rich_signature.offset == 128`,
				`pe.rich_signature.length == 16`,
				`pe.rich_signature.key == 0x01020304`,
				`defined pe.rich_signature.version_data`,
				`pe.rich_signature.version_data == ""`,
				`pe.rich_signature.version(0) == 0`,
				`pe.rich_signature.toolid(0) == 0`,
			},
		},
		{
			name: "absent_pe32",
			data: pefixture.New(false),
			predicates: []string{
				`pe.is_pe == 1`,
				`defined pe.rich_signature.offset`,
				`defined pe.rich_signature.length`,
				`defined pe.rich_signature.key`,
				`defined pe.rich_signature.raw_data`,
				`defined pe.rich_signature.clear_data`,
				`defined pe.rich_signature.version_data`,
				`defined pe.rich_signature.version(29500)`,
				`defined pe.rich_signature.version(29500, 259)`,
				`defined pe.rich_signature.toolid(259)`,
				`defined pe.rich_signature.toolid(259, 29500)`,
			},
		},
		{
			name: "absent_pe64",
			data: pefixture.New(true),
			predicates: []string{
				`pe.is_pe == 1`,
				`defined pe.rich_signature.offset`,
				`defined pe.rich_signature.key`,
				`defined pe.rich_signature.version(29500)`,
				`defined pe.rich_signature.toolid(259)`,
			},
		},
		{
			name: "non_pe",
			data: []byte("not a portable executable"),
			predicates: []string{
				`pe.is_pe == 0`,
				`defined pe.rich_signature.offset`,
				`defined pe.rich_signature.key`,
				`defined pe.rich_signature.version(29500)`,
				`defined pe.rich_signature.toolid(259)`,
			},
		},
		{
			name: "empty",
			data: nil,
			predicates: []string{
				`pe.is_pe == 0`,
				`defined pe.rich_signature.offset`,
				`defined pe.rich_signature.version(29500)`,
				`defined pe.rich_signature.toolid(259)`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkPEPaths(t, peProbeSource(tc.predicates), tc.data)
		})
	}
}
