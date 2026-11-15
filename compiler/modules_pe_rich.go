package compiler

import (
	"encoding/binary"
	"math"

	pe "github.com/cawalch/go-pe"
)

// newPERichSignatureSchema extends peVersionInfoSchema without mutating it so
// previously serialized programs continue matching isNativePESchema.
func newPERichSignatureSchema() *ModuleSchema {
	schema := cloneModuleSchema(peVersionInfoSchema)
	schema.Fields["rich_signature"] = ModuleField{
		Kind: ModuleStruct,
		Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"offset":       {Kind: ModuleInteger},
			"length":       {Kind: ModuleInteger},
			"key":          {Kind: ModuleInteger},
			"raw_data":     {Kind: ModuleString},
			"clear_data":   {Kind: ModuleString},
			"version_data": {Kind: ModuleString},
		}},
	}
	return schema
}

// peRichData caches one scan's parsed Rich header metadata without
// allocating byte-string wrappers until their individual fields are accessed.
type peRichData struct {
	header      *pe.RichHeader
	structVal   ModuleValue
	rawData     ModuleValue
	clearData   ModuleValue
	versionData ModuleValue
	valid       bool
}

func (image *peImage) loadRich() *peRichData {
	if image.rich != nil {
		return image.rich
	}
	if scanCanceled(peCancelDone(image.context)) {
		return &peRichData{}
	}
	image.rich = &peRichData{}
	header, err := image.file.RichHeader(peScanData(image.context))
	if err != nil || header == nil {
		return image.rich
	}
	image.rich.header = header
	image.rich.valid = true
	return image.rich
}

func (image *peImage) richField() ModuleValue {
	rich := image.loadRich()
	if !rich.valid {
		return ModuleValue{}
	}
	if rich.structVal.Type == ModuleUndefined {
		rich.structVal = peLazyStruct(func(field string) ModuleValue {
			switch field {
			case "offset":
				return IntegerValue(rich.header.Offset)
			case "length":
				return IntegerValue(rich.header.Length)
			case "key":
				return IntegerValue(int64(rich.header.Key))
			case "raw_data":
				if rich.rawData.Type == ModuleUndefined {
					rich.rawData = StringValue(string(rich.header.RawData))
				}
				return rich.rawData
			case "clear_data":
				if rich.clearData.Type == ModuleUndefined {
					rich.clearData = StringValue(string(rich.header.ClearData))
				}
				return rich.clearData
			case "version_data":
				if rich.versionData.Type == ModuleUndefined {
					rich.versionData = StringValue(peRichVersionData(rich.header))
				}
				return rich.versionData
			}
			return ModuleValue{}
		})
	}
	return rich.structVal
}

func peRichVersionData(header *pe.RichHeader) string {
	if len(header.Entries) == 0 {
		return ""
	}
	buf := make([]byte, len(header.Entries)*4)
	if len(header.ClearData) >= 16+len(header.Entries)*8 {
		for i := range header.Entries {
			off := 16 + i*8
			copy(buf[i*4:(i+1)*4], header.ClearData[off:off+4])
		}
		return string(buf)
	}
	for i, entry := range header.Entries {
		binary.LittleEndian.PutUint16(buf[i*4:], entry.Version)
		binary.LittleEndian.PutUint16(buf[i*4+2:], entry.ToolID)
	}
	return string(buf)
}

type peRichFilter struct {
	primary      int64
	secondary    int64
	hasSecondary bool
	byToolID     bool
}

func parseRichFilter(args []ModuleValue, byToolID bool) (peRichFilter, bool) {
	filter := peRichFilter{
		primary:  args[0].Integer,
		byToolID: byToolID,
	}
	if filter.primary < 0 || filter.primary > math.MaxUint16 {
		return filter, false
	}
	if len(args) == 2 {
		filter.secondary = args[1].Integer
		if filter.secondary < 0 || filter.secondary > math.MaxUint16 {
			return filter, false
		}
		filter.hasSecondary = true
	}
	return filter, true
}

func (f peRichFilter) addCount(total *int64, entry pe.RichEntry) bool {
	lhs, rhs := int64(entry.Version), int64(entry.ToolID)
	if f.byToolID {
		lhs, rhs = rhs, lhs
	}
	if lhs != f.primary || (f.hasSecondary && rhs != f.secondary) {
		return true
	}
	cnt := int64(entry.Count)
	if cnt > math.MaxInt64-*total {
		return false
	}
	*total += cnt
	return true
}

func (i *Interpreter) peRichQuery(args []ModuleValue, byToolID bool) ModuleValue {
	if len(args) < 1 || len(args) > 2 || i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	if args[0].Type != ModuleInteger || (len(args) == 2 && args[1].Type != ModuleInteger) {
		return ModuleValue{}
	}
	done := peCancelDone(i.matchContext)
	if scanCanceled(done) {
		return ModuleValue{}
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		return i.peHostRichQuery(data, args, byToolID)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	rich := image.loadRich()
	if !rich.valid {
		return ModuleValue{}
	}
	filter, ok := parseRichFilter(args, byToolID)
	if !ok {
		return IntegerValue(0)
	}
	var count int64
	for idx, entry := range rich.header.Entries {
		if scanCanceledAt(done, idx) {
			return ModuleValue{}
		}
		if !filter.addCount(&count, entry) {
			return ModuleValue{}
		}
	}
	return IntegerValue(count)
}

// Host snapshots take precedence over file parsing. Missing rich_signature or
// clear_data fields leave aggregate Rich queries undefined without falling back
// to raw input decoding.
func (i *Interpreter) peHostRichQuery(data ModuleValue, args []ModuleValue, byToolID bool) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	rs, exists := data.object.fields["rich_signature"]
	if !exists || rs.object == nil {
		return ModuleValue{}
	}
	clearVal, exists := rs.object.fields["clear_data"]
	if !exists || clearVal.Type != ModuleString {
		return ModuleValue{}
	}
	clearData := clearVal.String
	if len(clearData) < 16 || (len(clearData)-16)%8 != 0 {
		return ModuleValue{}
	}
	filter, ok := parseRichFilter(args, byToolID)
	if !ok {
		return IntegerValue(0)
	}
	done := peCancelDone(i.matchContext)
	var count int64
	for pos := 16; pos+8 <= len(clearData); pos += 8 {
		if scanCanceledAt(done, pos) {
			return ModuleValue{}
		}
		entry := pe.RichEntry{
			Version: binary.LittleEndian.Uint16([]byte(clearData[pos : pos+2])),
			ToolID:  binary.LittleEndian.Uint16([]byte(clearData[pos+2 : pos+4])),
			Count:   binary.LittleEndian.Uint32([]byte(clearData[pos+4 : pos+8])),
		}
		if !filter.addCount(&count, entry) {
			return ModuleValue{}
		}
	}
	return IntegerValue(count)
}
