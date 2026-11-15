package pefixture

import (
	"encoding/binary"
	"unicode/utf16"
)

// VersionStringEntry describes one String entry inside a StringTable.
type VersionStringEntry struct {
	Key           string
	Value         string
	RawKeyUnits   []uint16
	RawValueUnits []uint16
	// OmitValue sets wValueLength=0 with no value UTF-16 units emitted.
	OmitValue bool
}

// VersionStringTableSpec describes one StringTable inside StringFileInfo.
type VersionStringTableSpec struct {
	Key     string
	Entries []VersionStringEntry
}

// VersionInfoSpec describes one VS_VERSION_INFO resource payload.
type VersionInfoSpec struct {
	StringTables       []VersionStringTableSpec
	Translations       []uint32
	IncludeVarFileInfo bool
}

type versionBlockSpec struct {
	key         string
	rawKeyUnits []uint16
	wType       uint16
	valueLen    uint16
	valueBytes  []byte
	children    func([]byte) []byte
}

func appendAligned4(buf []byte) []byte {
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func appendUTF16NUL(buf []byte, s string, raw []uint16) []byte {
	units := raw
	if units == nil {
		units = utf16.Encode([]rune(s))
	}
	for _, u := range units {
		buf = binary.LittleEndian.AppendUint16(buf, u)
	}
	return binary.LittleEndian.AppendUint16(buf, 0)
}

func appendVersionBlock(buf []byte, spec versionBlockSpec) []byte {
	buf = appendAligned4(buf)
	start := len(buf)
	buf = binary.LittleEndian.AppendUint16(buf, 0)
	buf = binary.LittleEndian.AppendUint16(buf, spec.valueLen)
	buf = binary.LittleEndian.AppendUint16(buf, spec.wType)
	buf = appendUTF16NUL(buf, spec.key, spec.rawKeyUnits)
	if len(spec.valueBytes) > 0 {
		buf = appendAligned4(buf)
		buf = append(buf, spec.valueBytes...)
	}
	if spec.children != nil {
		buf = appendAligned4(buf)
		buf = spec.children(buf)
	}
	binary.LittleEndian.PutUint16(buf[start:], uint16(len(buf)-start)) //checkednarrow:ignore bounded fixture block size
	return buf
}

func appendVersionStringBlock(buf []byte, entry VersionStringEntry) []byte {
	var valLen uint16
	var valBytes []byte
	if !entry.OmitValue {
		units := entry.RawValueUnits
		if units == nil {
			units = utf16.Encode([]rune(entry.Value))
		}
		valLen = uint16(len(units) + 1) //checkednarrow:ignore bounded fixture string lengths
		valBytes = make([]byte, 0, len(units)*2+2)
		for _, u := range units {
			valBytes = binary.LittleEndian.AppendUint16(valBytes, u)
		}
		valBytes = binary.LittleEndian.AppendUint16(valBytes, 0)
	}
	return appendVersionBlock(buf, versionBlockSpec{
		key:         entry.Key,
		rawKeyUnits: entry.RawKeyUnits,
		wType:       1,
		valueLen:    valLen,
		valueBytes:  valBytes,
	})
}

func appendStringTableBlock(buf []byte, tbl VersionStringTableSpec) []byte {
	key := tbl.Key
	if key == "" {
		key = "040904b0"
	}
	return appendVersionBlock(buf, versionBlockSpec{
		key:   key,
		wType: 1,
		children: func(dst []byte) []byte {
			for _, entry := range tbl.Entries {
				dst = appendVersionStringBlock(dst, entry)
			}
			return dst
		},
	})
}

func appendVarFileInfoBlock(buf []byte, translations []uint32) []byte {
	var bytes []byte
	for _, tr := range translations {
		bytes = binary.LittleEndian.AppendUint32(bytes, tr)
	}
	return appendVersionBlock(buf, versionBlockSpec{
		key:   "VarFileInfo",
		wType: 1,
		children: func(dst []byte) []byte {
			return appendVersionBlock(dst, versionBlockSpec{
				key:        "Translation",
				wType:      0,
				valueLen:   uint16(len(bytes)), //checkednarrow:ignore bounded fixture translation size
				valueBytes: bytes,
			})
		},
	})
}

// VersionInfoPayload encodes one VS_VERSION_INFO resource payload.
func VersionInfoPayload(spec VersionInfoSpec) []byte {
	fixed := make([]byte, 52)
	binary.LittleEndian.PutUint32(fixed[0:], 0xFEEF04BD)
	binary.LittleEndian.PutUint32(fixed[4:], 0x00010000)

	return appendVersionBlock(nil, versionBlockSpec{
		key:        "VS_VERSION_INFO",
		wType:      0,
		valueLen:   52,
		valueBytes: fixed,
		children: func(dst []byte) []byte {
			if len(spec.StringTables) > 0 {
				dst = appendVersionBlock(dst, versionBlockSpec{
					key:   "StringFileInfo",
					wType: 1,
					children: func(inner []byte) []byte {
						for _, tbl := range spec.StringTables {
							inner = appendStringTableBlock(inner, tbl)
						}
						return inner
					},
				})
			}
			if spec.IncludeVarFileInfo || len(spec.Translations) > 0 {
				dst = appendVarFileInfoBlock(dst, spec.Translations)
			}
			return dst
		},
	})
}

// VersionInfoPE builds a PE32 or PE32+ image containing one RT_VERSION resource
// leaf for each spec in specs.
func VersionInfoPE(is64 bool, specs ...VersionInfoSpec) []byte {
	idEntries := make([]ResourceEntrySpec, len(specs))
	for i, spec := range specs {
		idEntries[i] = ResourceEntrySpec{
			ID: uint32(i + 1), //checkednarrow:ignore positive bounded fixture ID
			Subdir: &ResourceNodeSpec{
				Entries: []ResourceEntrySpec{
					{
						ID:   1033,
						Leaf: &ResourceLeafSpec{Payload: VersionInfoPayload(spec)},
					},
				},
			},
		}
	}
	return WithResources(New(is64), is64, &ResourceNodeSpec{
		Entries: []ResourceEntrySpec{
			{
				ID:     16,
				Subdir: &ResourceNodeSpec{Entries: idEntries},
			},
		},
	})
}
