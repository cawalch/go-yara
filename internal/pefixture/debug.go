package pefixture

import "encoding/binary"

// DebugEntrySpec configures one synthetic IMAGE_DEBUG_DIRECTORY record and
// its optional payload.
type DebugEntrySpec struct {
	Type           uint32
	Payload        []byte
	RVAOnly        bool
	PtrOnly        bool
	InOverlay      bool
	ConflictOffset uint32
	HasCustomSize  bool
	CustomSize     uint32
	OutOfPrefix    int // Inserts zero bytes before the payload in overlay/tail space.
}

// RSDSPayload builds a CodeView PDB 7.0 ("RSDS") payload with the given raw
// path bytes (callers must include trailing NUL when testing terminated paths).
func RSDSPayload(path []byte) []byte {
	out := make([]byte, 24+len(path))
	copy(out[0:4], "RSDS")
	for i := range 16 {
		out[4+i] = byte(i + 1)
	}
	binary.LittleEndian.PutUint32(out[20:24], 1)
	copy(out[24:], path)
	return out
}

// NB10Payload builds a CodeView PDB 2.0 ("NB10") payload with the given raw
// path bytes (callers must include trailing NUL when testing terminated paths).
func NB10Payload(path []byte) []byte {
	out := make([]byte, 16+len(path))
	copy(out[0:4], "NB10")
	binary.LittleEndian.PutUint32(out[4:8], 0)
	binary.LittleEndian.PutUint32(out[8:12], 0x56781234)
	binary.LittleEndian.PutUint32(out[12:16], 2)
	copy(out[16:], path)
	return out
}

// DebugPE builds a PE32 or PE32+ image populated with the supplied debug
// directory entries.
func DebugPE(is64 bool, specs ...DebugEntrySpec) []byte {
	base := New(is64)
	if len(specs) == 0 {
		return base
	}

	const (
		tableRaw = 0x400
		tableRVA = 0x2000
		entSize  = 28
	)
	tableLen := len(specs) * entSize
	mappedCursor := (tableLen + 15) &^ 15

	type placement struct {
		offset int
		rva    uint32
		rawPtr uint32
		size   uint32
	}
	placements := make([]placement, len(specs))
	maxOverlayEnd := 0

	// First allocate mapped payloads sequentially inside .data.
	for i, spec := range specs {
		if len(spec.Payload) == 0 && !spec.HasCustomSize {
			continue
		}
		size := uint32(len(spec.Payload)) //checkednarrow:ignore bounded fixture payload size
		if spec.HasCustomSize {
			size = spec.CustomSize
		}
		if spec.InOverlay || spec.OutOfPrefix > 0 {
			continue
		}
		off := tableRaw + mappedCursor
		rva := uint32(tableRVA + mappedCursor) //checkednarrow:ignore bounded fixture payload size
		rawPtr := uint32(off)                  //checkednarrow:ignore bounded fixture payload offset
		if spec.RVAOnly {
			rawPtr = 0
		}
		if spec.PtrOnly {
			rva = 0
		}
		if spec.ConflictOffset != 0 {
			rawPtr = spec.ConflictOffset
		}
		placements[i] = placement{offset: off, rva: rva, rawPtr: rawPtr, size: size}
		mappedCursor += (len(spec.Payload) + 15) &^ 15
	}

	rawDataSize := ((mappedCursor + 0x1ff) / 0x200) * 0x200
	if rawDataSize < 0x200 {
		rawDataSize = 0x200
	}
	overlayCursor := tableRaw + rawDataSize
	for i, spec := range specs {
		if !spec.InOverlay && spec.OutOfPrefix <= 0 {
			continue
		}
		if spec.OutOfPrefix > 0 && overlayCursor < spec.OutOfPrefix {
			overlayCursor = spec.OutOfPrefix
		}
		size := uint32(len(spec.Payload)) //checkednarrow:ignore bounded fixture payload size
		if spec.HasCustomSize {
			size = spec.CustomSize
		}
		rawPtr := uint32(overlayCursor) //checkednarrow:ignore bounded fixture overlay offset
		rva := uint32(0)
		if spec.ConflictOffset != 0 {
			rva = tableRVA
			rawPtr = spec.ConflictOffset
		}
		placements[i] = placement{offset: overlayCursor, rva: rva, rawPtr: rawPtr, size: size}
		overlayCursor += (len(spec.Payload) + 15) &^ 15
		if overlayCursor > maxOverlayEnd {
			maxOverlayEnd = overlayCursor
		}
	}

	totalSize := max(len(base), tableRaw+rawDataSize)
	if maxOverlayEnd > totalSize {
		totalSize = maxOverlayEnd
	}
	out := make([]byte, totalSize)
	copy(out, base)

	optStart := 0x98
	optSize := 224
	ddOffset := optStart + 96 + 6*8
	if is64 {
		optSize = 240
		ddOffset = optStart + 112 + 6*8
	}
	// Update .data VirtualSize / SizeOfRawData and OptionalHeader.SizeOfImage.
	sec1 := optStart + optSize + 40
	virtualSize := uint32(max(0x180, mappedCursor)) //checkednarrow:ignore bounded fixture section size
	sizeOfRaw := uint32(rawDataSize)                //checkednarrow:ignore bounded fixture raw size
	sizeOfImage := ((tableRVA + virtualSize) + 0xfff) &^ 0xfff
	binary.LittleEndian.PutUint32(out[sec1+8:], virtualSize)
	binary.LittleEndian.PutUint32(out[sec1+16:], sizeOfRaw)
	binary.LittleEndian.PutUint32(out[optStart+56:], sizeOfImage)
	binary.LittleEndian.PutUint32(out[ddOffset:], tableRVA)
	binary.LittleEndian.PutUint32(out[ddOffset+4:], uint32(tableLen)) //checkednarrow:ignore bounded table size

	for i, spec := range specs {
		ent := out[tableRaw+i*entSize : tableRaw+(i+1)*entSize]
		binary.LittleEndian.PutUint32(ent[12:16], spec.Type)
		p := placements[i]
		binary.LittleEndian.PutUint32(ent[16:20], p.size)
		binary.LittleEndian.PutUint32(ent[20:24], p.rva)
		binary.LittleEndian.PutUint32(ent[24:28], p.rawPtr)
		if len(spec.Payload) > 0 && p.offset+len(spec.Payload) <= len(out) {
			copy(out[p.offset:], spec.Payload)
		}
	}
	return out
}
