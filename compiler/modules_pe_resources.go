package compiler

import (
	"encoding/binary"
	"unicode/utf16"

	pe "github.com/cawalch/go-pe"
)

func addPEResourcesSchemaFields(schema *ModuleSchema) {
	schema.Fields["resource_timestamp"] = ModuleField{Kind: ModuleInteger}
	schema.Fields["resource_version"] = ModuleField{
		Kind: ModuleStruct,
		Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"major": {Kind: ModuleInteger},
			"minor": {Kind: ModuleInteger},
		}},
	}
	schema.Fields["number_of_resources"] = ModuleField{Kind: ModuleInteger}
	schema.Fields["resources"] = ModuleField{
		Kind: ModuleArray,
		Element: &ModuleField{
			Kind: ModuleStruct,
			Struct: &ModuleSchema{Fields: map[string]ModuleField{
				"offset":          {Kind: ModuleInteger},
				"rva":             {Kind: ModuleInteger},
				"length":          {Kind: ModuleInteger},
				"type":            {Kind: ModuleInteger},
				"id":              {Kind: ModuleInteger},
				"language":        {Kind: ModuleInteger},
				"type_string":     {Kind: ModuleString},
				"name_string":     {Kind: ModuleString},
				"language_string": {Kind: ModuleString},
			}},
		},
	}
	for name, number := range peResourceConstants {
		value := IntegerValue(number)
		schema.Fields[name] = ModuleField{Kind: ModuleInteger, Constant: &value}
	}
}

// peResourceData caches one scan's parsed resource directory metadata without
// materializing resource arrays or copying payloads. When valid is false,
// all resource fields and locale/language queries remain undefined.
type peResourceData struct {
	records   []pe.ResourceRecord
	details   ModuleValue
	version   ModuleValue
	fileSize  int64
	timestamp uint32
	major     uint16
	minor     uint16
	valid     bool
	present   bool
}

func (image *peImage) loadResources() *peResourceData {
	if image.resources != nil {
		return image.resources
	}
	done := peCancelDone(image.context)
	if scanCanceled(done) {
		return &peResourceData{}
	}
	image.resources = &peResourceData{fileSize: image.context.FileSize}
	dir, err := image.file.Resources(peScanData(image.context))
	if err != nil {
		return image.resources
	}
	image.resources.valid = true
	if dir == nil {
		return image.resources
	}
	image.resources.present = true
	image.resources.timestamp = dir.TimeDateStamp
	image.resources.major = dir.MajorVersion
	image.resources.minor = dir.MinorVersion
	// Match libyara's three-level resource traversal (Type, ID/Name, Language)
	// by excluding deeper custom subtrees from YARA's resource array.
	hasDeep := false
	for i := range dir.Records {
		if len(dir.Records[i].Path) > 3 {
			hasDeep = true
			break
		}
	}
	if !hasDeep {
		image.resources.records = dir.Records
		return image.resources
	}
	filtered := make([]pe.ResourceRecord, 0, len(dir.Records))
	for i := range dir.Records {
		if len(dir.Records[i].Path) <= 3 {
			filtered = append(filtered, dir.Records[i])
		}
	}
	image.resources.records = filtered
	return image.resources
}

func (image *peImage) resourceField(name string) ModuleValue {
	res := image.loadResources()
	if !res.valid {
		return ModuleValue{}
	}
	switch name {
	case "resource_timestamp":
		if res.present {
			return IntegerValue(int64(res.timestamp))
		}
		return ModuleValue{}
	case "resource_version":
		if !res.present {
			return ModuleValue{}
		}
		if res.version.Type == ModuleUndefined {
			res.version = peVersion(res.major, res.minor)
		}
		return res.version
	case "number_of_resources":
		return IntegerValue(int64(len(res.records)))
	case "resources":
		if res.details.Type == ModuleUndefined {
			done := peCancelDone(image.context)
			values := make([]ModuleValue, len(res.records))
			for i := range values {
				if scanCanceledAt(done, i) {
					return ModuleValue{}
				}
				values[i] = peResourceFields(&res.records[i], image.file, res.fileSize)
			}
			res.details = peArray(values)
		}
		return res.details
	}
	return ModuleValue{}
}

func peResourceFields(record *pe.ResourceRecord, file *pe.File, fileSize int64) ModuleValue {
	return peLazyStruct(func(name string) ModuleValue {
		switch name {
		case "rva":
			return IntegerValue(int64(record.DataRVA))
		case "length":
			return IntegerValue(int64(record.Size))
		case "offset":
			if offset := peRVAToOffset(file, record.DataRVA, fileSize); offset >= 0 {
				return IntegerValue(offset)
			}
		case "type", "type_string":
			return peResourceComponentValue(record.Path, 0, name == "type_string")
		case "id", "name_string":
			return peResourceComponentValue(record.Path, 1, name == "name_string")
		case "language", "language_string":
			return peResourceComponentValue(record.Path, 2, name == "language_string")
		}
		return ModuleValue{}
	})
}

func peResourceComponentValue(path []pe.ResourceComponent, index int, wantString bool) ModuleValue {
	if index >= len(path) {
		return ModuleValue{}
	}
	comp := path[index]
	if comp.Named {
		if wantString {
			return StringValue(peUTF16LEBytes(comp.Name))
		}
		return ModuleValue{}
	}
	if !wantString {
		return IntegerValue(int64(comp.ID))
	}
	return ModuleValue{}
}

// libyara exposes resource component strings as raw little-endian UTF-16 byte
// slices rather than transcoded UTF-8 strings.
func peUTF16LEBytes(s string) string {
	if s == "" {
		return ""
	}
	units := utf16.Encode([]rune(s))
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[i*2:], u)
	}
	return string(buf)
}

func (i *Interpreter) peLocaleQuery(args []ModuleValue, maskPrimary bool) ModuleValue {
	if len(args) != 1 || args[0].Type != ModuleInteger || i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	done := peCancelDone(i.matchContext)
	if scanCanceled(done) {
		return ModuleValue{}
	}
	target := args[0].Integer
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostResourceLocaleQuery(data, peResourceLocaleQuery{target: target, maskPrimary: maskPrimary, done: done})
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	res := image.loadResources()
	if !res.valid {
		return ModuleValue{}
	}
	for idx := range res.records {
		if scanCanceledAt(done, idx) {
			return ModuleValue{}
		}
		path := res.records[idx].Path
		if len(path) < 3 || path[2].Named {
			continue
		}
		langID := int64(path[2].ID)
		if maskPrimary {
			// Match libyara's low-byte language mask (language & 0xff).
			langID &= 0xff
		}
		if langID == target {
			return IntegerValue(1)
		}
	}
	return IntegerValue(0)
}

type peResourceLocaleQuery struct {
	target      int64
	maskPrimary bool
	done        <-chan struct{}
}

func peHostResourceLocaleQuery(data ModuleValue, q peResourceLocaleQuery) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	details := data.object.fields["resources"]
	if details.object == nil {
		return ModuleValue{}
	}
	for idx, entry := range details.object.elements {
		if scanCanceledAt(q.done, idx) {
			return ModuleValue{}
		}
		if entry.object == nil {
			continue
		}
		lang := entry.object.fields["language"]
		if lang.Type != ModuleInteger {
			continue
		}
		langID := lang.Integer
		if q.maskPrimary {
			if langID < 0 {
				continue
			}
			langID &= 0xff
		}
		if langID == q.target {
			return IntegerValue(1)
		}
	}
	return IntegerValue(0)
}
