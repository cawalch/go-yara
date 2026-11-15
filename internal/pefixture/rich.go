package pefixture

import "encoding/binary"

// RichEntry describes one (version, toolid, count) tuple inside a Rich header.
type RichEntry struct {
	ToolID  uint16
	Version uint16
	Count   uint32
}

// RichOptions configures synthetic Rich header generation for valid and
// malformed PE test fixtures.
type RichOptions struct {
	Key           uint32
	ZeroKey       bool
	HeaderPadding [3]uint32
	TailZeroWords int
	Entries       []RichEntry
}

// RichPE returns a PE32 or PE32+ image containing a DOS-stub Rich header built
// from opts.
func RichPE(is64 bool, opts RichOptions) []byte {
	return WithRichHeader(New(is64), is64, opts)
}

// WithRichHeader inserts a Rich header built from opts at offset 0x80 in base
// (as produced by New) and shifts the PE headers and section raw offsets.
func WithRichHeader(base []byte, is64 bool, opts RichOptions) []byte {
	key := opts.Key
	if key == 0 && !opts.ZeroKey {
		key = 0x11223344
	}

	clearLen := 16 + len(opts.Entries)*8
	clearData := make([]byte, clearLen)
	copy(clearData[0:4], "DanS")
	binary.LittleEndian.PutUint32(clearData[4:8], opts.HeaderPadding[0])
	binary.LittleEndian.PutUint32(clearData[8:12], opts.HeaderPadding[1])
	binary.LittleEndian.PutUint32(clearData[12:16], opts.HeaderPadding[2])
	for i, entry := range opts.Entries {
		off := 16 + i*8
		binary.LittleEndian.PutUint16(clearData[off:off+2], entry.Version)
		binary.LittleEndian.PutUint16(clearData[off+2:off+4], entry.ToolID)
		binary.LittleEndian.PutUint32(clearData[off+4:off+8], entry.Count)
	}

	tailWords := max(opts.TailZeroWords, 0)
	richBlockLen := clearLen + 8 + tailWords*4
	richBlock := make([]byte, richBlockLen)
	for off := 0; off < clearLen; off += 4 {
		w := binary.LittleEndian.Uint32(clearData[off : off+4])
		binary.LittleEndian.PutUint32(richBlock[off:off+4], w^key)
	}
	copy(richBlock[clearLen:clearLen+4], "Rich")
	binary.LittleEndian.PutUint32(richBlock[clearLen+4:clearLen+8], key)

	newPEOffset := 0x80 + richBlockLen
	const headerSliceLen = 0x180 // base[0x80:0x200] covers PE, COFF, Optional, and section headers
	newHeadersEnd := ((newPEOffset + headerSliceLen + 0x1ff) / 0x200) * 0x200
	shift := newHeadersEnd - 0x200

	out := make([]byte, len(base)+shift)
	copy(out[:0x80], base[:0x80])
	copy(out[0x80:newPEOffset], richBlock)
	binary.LittleEndian.PutUint32(out[0x3c:0x40], uint32(newPEOffset)) //checkednarrow:ignore synthetic fixture header offset
	copy(out[newPEOffset:newPEOffset+headerSliceLen], base[0x80:0x200])
	binary.LittleEndian.PutUint32(out[newPEOffset+24+60:], uint32(newHeadersEnd)) //checkednarrow:ignore synthetic fixture header size

	optionalSize := 224
	if is64 {
		optionalSize = 240
	}
	numSections := int(binary.LittleEndian.Uint16(out[newPEOffset+4+2:]))
	secBase := newPEOffset + 24 + optionalSize
	for i := range numSections {
		rawPtrOff := secBase + i*40 + 20
		if rawPtr := binary.LittleEndian.Uint32(out[rawPtrOff:]); rawPtr != 0 {
			binary.LittleEndian.PutUint32(out[rawPtrOff:], rawPtr+uint32(shift)) //checkednarrow:ignore synthetic fixture raw offset
		}
	}
	copy(out[newHeadersEnd:], base[0x200:])
	return out
}
