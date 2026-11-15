package pefixture

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// ResourceNodeSpec describes an IMAGE_RESOURCE_DIRECTORY node for synthetic
// fixtures. Reusing the same *ResourceNodeSpec pointer across entries emits a
// shared DAG subtree.
type ResourceNodeSpec struct {
	Characteristics uint32
	TimeDateStamp   uint32
	MajorVersion    uint16
	MinorVersion    uint16
	Entries         []ResourceEntrySpec
	// ExtraTailBytes appends zero padding inside .rsrc before placing leaf
	// payloads when set on the root node.
	ExtraTailBytes int
}

// ResourceEntrySpec describes one IMAGE_RESOURCE_DIRECTORY_ENTRY inside a node.
type ResourceEntrySpec struct {
	Named        bool
	Name         string
	RawNameUnits []uint16
	ID           uint32
	Subdir       *ResourceNodeSpec
	Leaf         *ResourceLeafSpec
}

// ResourceLeafSpec describes one IMAGE_RESOURCE_DATA_ENTRY leaf.
type ResourceLeafSpec struct {
	Payload       []byte
	CustomRVA     uint32
	HasCustomRVA  bool
	CustomSize    uint32
	HasCustomSize bool
	CodePage      uint32
	Reserved      uint32
}

// WithResources appends a .rsrc section containing root to a copy of base and
// wires DataDirectory[2] to it.
func WithResources(base []byte, is64 bool, root *ResourceNodeSpec) []byte {
	out := append([]byte(nil), base...)
	coff := out[0x84:]
	numSec := int(binary.LittleEndian.Uint16(coff[2:4]))
	optSize := int(binary.LittleEndian.Uint16(coff[16:18]))
	secTableStart := 0x98 + optSize
	prevSec := out[secTableStart+(numSec-1)*40:]
	prevVA := binary.LittleEndian.Uint32(prevSec[12:])
	prevSpan := max(binary.LittleEndian.Uint32(prevSec[8:]), binary.LittleEndian.Uint32(prevSec[16:]))
	rsrcRVA := (prevVA + prevSpan + 0xfff) &^ 0xfff

	filePad := (len(out) + 511) &^ 511
	if len(out) < filePad {
		out = append(out, make([]byte, filePad-len(out))...)
	}
	rsrcFileOff := len(out)

	var rsrc []byte
	nodeOffsets := make(map[*ResourceNodeSpec]uint32)
	type pendingEntry struct {
		entryOff int
		entry    ResourceEntrySpec
	}
	var queue []*ResourceNodeSpec
	var namedPendings []pendingEntry
	var leafPendings []pendingEntry

	allocNode := func(n *ResourceNodeSpec) uint32 {
		if off, ok := nodeOffsets[n]; ok {
			return off
		}
		off := uint32(len(rsrc)) //checkednarrow:ignore bounded fixture offsets
		nodeOffsets[n] = off
		size := 16 + len(n.Entries)*8
		rsrc = append(rsrc, make([]byte, size)...)
		binary.LittleEndian.PutUint32(rsrc[off:], n.Characteristics)
		binary.LittleEndian.PutUint32(rsrc[off+4:], n.TimeDateStamp)
		binary.LittleEndian.PutUint16(rsrc[off+8:], n.MajorVersion)
		binary.LittleEndian.PutUint16(rsrc[off+10:], n.MinorVersion)
		var namedCount, idCount uint16
		for _, e := range n.Entries {
			if e.Named {
				namedCount++
			} else {
				idCount++
			}
		}
		binary.LittleEndian.PutUint16(rsrc[off+12:], namedCount)
		binary.LittleEndian.PutUint16(rsrc[off+14:], idCount)
		queue = append(queue, n)
		return off
	}

	allocNode(root)
	for qi := 0; qi < len(queue); qi++ {
		n := queue[qi]
		baseOff := int(nodeOffsets[n])
		for i, e := range n.Entries {
			eOff := baseOff + 16 + i*8
			if e.Named {
				namedPendings = append(namedPendings, pendingEntry{entryOff: eOff, entry: e})
			} else {
				binary.LittleEndian.PutUint32(rsrc[eOff:], e.ID)
			}
			if e.Subdir != nil {
				childOff := allocNode(e.Subdir)
				binary.LittleEndian.PutUint32(rsrc[eOff+4:], 0x80000000|childOff)
			} else {
				leafPendings = append(leafPendings, pendingEntry{entryOff: eOff, entry: e})
			}
		}
	}

	for _, pe := range namedPendings {
		units := pe.entry.RawNameUnits
		if units == nil {
			units = utf16.Encode([]rune(pe.entry.Name))
		}
		strOff := uint32(len(rsrc)) //checkednarrow:ignore bounded fixture offsets
		rsrc = append(rsrc, make([]byte, 2+len(units)*2)...)
		binary.LittleEndian.PutUint16(rsrc[strOff:], uint16(len(units))) //checkednarrow:ignore bounded fixture string lengths
		for i, u := range units {
			binary.LittleEndian.PutUint16(rsrc[int(strOff)+2+i*2:], u)
		}
		binary.LittleEndian.PutUint32(rsrc[pe.entryOff:], 0x80000000|strOff)
	}

	dataEntryOffs := make([]uint32, len(leafPendings))
	for i, lp := range leafPendings {
		deOff := uint32(len(rsrc)) //checkednarrow:ignore bounded fixture offsets
		dataEntryOffs[i] = deOff
		rsrc = append(rsrc, make([]byte, 16)...)
		binary.LittleEndian.PutUint32(rsrc[lp.entryOff+4:], deOff)
	}

	if root.ExtraTailBytes > 0 {
		rsrc = append(rsrc, make([]byte, root.ExtraTailBytes)...)
	}
	for i, lp := range leafPendings {
		leaf := lp.entry.Leaf
		if leaf == nil {
			leaf = &ResourceLeafSpec{}
		}
		deOff := int(dataEntryOffs[i])
		var dataRVA uint32
		if leaf.HasCustomRVA {
			dataRVA = leaf.CustomRVA
		} else {
			payloadOff := len(rsrc)
			rsrc = append(rsrc, leaf.Payload...)
			dataRVA = rsrcRVA + uint32(payloadOff) //checkednarrow:ignore bounded fixture offsets
		}
		size := uint32(len(leaf.Payload)) //checkednarrow:ignore bounded fixture size
		if leaf.HasCustomSize {
			size = leaf.CustomSize
		}
		binary.LittleEndian.PutUint32(rsrc[deOff:], dataRVA)
		binary.LittleEndian.PutUint32(rsrc[deOff+4:], size)
		binary.LittleEndian.PutUint32(rsrc[deOff+8:], leaf.CodePage)
		binary.LittleEndian.PutUint32(rsrc[deOff+12:], leaf.Reserved)
	}

	rsrcVirtualSize := uint32(len(rsrc)) //checkednarrow:ignore bounded fixture size
	rawPadded := (len(rsrc) + 511) &^ 511
	if rawPadded == 0 {
		rawPadded = 512
	}
	if len(rsrc) < rawPadded {
		rsrc = append(rsrc, make([]byte, rawPadded-len(rsrc))...)
	}
	out = append(out, rsrc...)

	coff = out[0x84:]
	binary.LittleEndian.PutUint16(coff[2:4], uint16(numSec+1)) //checkednarrow:ignore bounded section count
	newSec := out[secTableStart+numSec*40:]
	copy(newSec[:8], ".rsrc\x00\x00\x00")
	binary.LittleEndian.PutUint32(newSec[8:], rsrcVirtualSize)
	binary.LittleEndian.PutUint32(newSec[12:], rsrcRVA)
	binary.LittleEndian.PutUint32(newSec[16:], uint32(len(rsrc)))   //checkednarrow:ignore bounded fixture size
	binary.LittleEndian.PutUint32(newSec[20:], uint32(rsrcFileOff)) //checkednarrow:ignore bounded fixture offset
	binary.LittleEndian.PutUint32(newSec[36:], 0x40000040)

	dirOff := 0x108
	if is64 {
		dirOff = 0x118
	}
	binary.LittleEndian.PutUint32(out[dirOff:], rsrcRVA)
	binary.LittleEndian.PutUint32(out[dirOff+4:], rsrcVirtualSize)

	opt := out[0x98:]
	imageSize := (rsrcRVA + uint32(len(rsrc)) + 0xfff) &^ 0xfff //checkednarrow:ignore bounded fixture size
	binary.LittleEndian.PutUint32(opt[56:], imageSize)
	return out
}

// Resources builds a PE32 or PE32+ image containing leaves standard 3-level
// (Type=10/RCDATA, ID=1..leaves, Lang=1033) resource entries.
func Resources(is64 bool, leaves int) []byte {
	entries := make([]ResourceEntrySpec, leaves)
	for i := range leaves {
		entries[i] = ResourceEntrySpec{
			ID: uint32(i + 1), //checkednarrow:ignore positive bounded loop index
			Subdir: &ResourceNodeSpec{
				Entries: []ResourceEntrySpec{
					{
						ID: 1033,
						Leaf: &ResourceLeafSpec{
							Payload:  fmt.Appendf(nil, "res-%05d", i),
							CodePage: 1200,
						},
					},
				},
			},
		}
	}
	return WithResources(New(is64), is64, &ResourceNodeSpec{
		TimeDateStamp: 0x12345678,
		MajorVersion:  2,
		MinorVersion:  5,
		Entries: []ResourceEntrySpec{
			{
				ID:     10,
				Subdir: &ResourceNodeSpec{Entries: entries},
			},
		},
	})
}
