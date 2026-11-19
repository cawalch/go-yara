package compiler

import (
	"slices"
	"unicode/utf16"

	pe "github.com/cawalch/go-pe"
)

const (
	peVersionResourceType = 16
	peVersionKeyMaxUnits  = 63
	peVersionValMaxUnits  = 255
)

func addPEVersionInfoSchemaFields(schema *ModuleSchema) {
	schema.Fields["version_info"] = ModuleField{
		Kind:    ModuleDictionary,
		Element: &ModuleField{Kind: ModuleString},
	}
	schema.Fields["version_info_list"] = ModuleField{
		Kind: ModuleArray,
		Element: &ModuleField{
			Kind: ModuleStruct,
			Struct: &ModuleSchema{Fields: map[string]ModuleField{
				"key":   {Kind: ModuleString},
				"value": {Kind: ModuleString},
			}},
		},
	}
	schema.Fields["number_of_version_infos"] = ModuleField{Kind: ModuleInteger}
}

type peVersionEntry struct {
	key   string
	value string
}

// peVersionData caches one scan's parsed RT_VERSION entries without
// materializing dictionary maps or list element wrappers until requested.
type peVersionData struct {
	entries []peVersionEntry
	dict    ModuleValue
	list    ModuleValue
	valid   bool
}

func (image *peImage) loadVersionInfo() *peVersionData {
	if image.versionInfo != nil {
		return image.versionInfo
	}
	done := peCancelDone(image.context)
	if scanCanceled(done) {
		return &peVersionData{}
	}
	res := image.loadResources()
	image.versionInfo = &peVersionData{}
	if !res.valid {
		return image.versionInfo
	}
	if !res.present || len(res.records) == 0 {
		image.versionInfo.valid = true
		return image.versionInfo
	}

	data := peScanData(image.context)
	var entries []peVersionEntry
	for idx := range res.records {
		if scanCanceledAt(done, idx) {
			image.versionInfo = &peVersionData{}
			return image.versionInfo
		}
		rec := res.records[idx]
		if len(rec.Path) == 0 || rec.Path[0].Named || rec.Path[0].ID != peVersionResourceType {
			continue
		}
		if rec.Size == 0 || uint64(rec.Size) > uint64(len(data)) || uint64(rec.Size) > pe.MaxVersionPayloadBytes {
			return image.versionInfo
		}
		payload, err := image.file.ResourcePayload(data, rec)
		if err != nil {
			return image.versionInfo
		}
		vi, err := pe.ParseVersionInfo(payload)
		if err != nil {
			return image.versionInfo
		}
		for _, tbl := range vi.StringTables {
			for _, item := range tbl.Entries {
				entries = append(entries, peVersionEntry{
					key:   peVersionString(item.Key, peVersionKeyMaxUnits),
					value: peVersionString(item.Value, peVersionValMaxUnits),
				})
			}
		}
	}
	image.versionInfo.entries = entries
	image.versionInfo.valid = true
	return image.versionInfo
}

func (image *peImage) versionInfoField(name string) ModuleValue {
	ver := image.loadVersionInfo()
	if !ver.valid {
		return ModuleValue{}
	}
	switch name {
	case "number_of_version_infos":
		return IntegerValue(int64(len(ver.entries)))
	case "version_info":
		if ver.dict.Type == ModuleUndefined {
			done := peCancelDone(image.context)
			fields := make(map[string]ModuleValue, len(ver.entries))
			keys := make([]string, 0, len(ver.entries))
			for i, entry := range ver.entries {
				if scanCanceledAt(done, i) {
					return ModuleValue{}
				}
				if _, exists := fields[entry.key]; !exists {
					keys = append(keys, entry.key)
				}
				// Match libyara dictionary overwrite policy (last entry wins).
				fields[entry.key] = StringValue(entry.value)
			}
			slices.Sort(keys)
			ver.dict = ModuleValue{
				Type: ModuleDictionary,
				object: &moduleObject{
					kind:   ModuleDictionary,
					fields: fields,
					keys:   keys,
				},
			}
		}
		return ver.dict
	case "version_info_list":
		if ver.list.Type == ModuleUndefined {
			done := peCancelDone(image.context)
			elements := make([]ModuleValue, len(ver.entries))
			for i := range ver.entries {
				if scanCanceledAt(done, i) {
					return ModuleValue{}
				}
				elements[i] = peVersionListEntryFields(ver.entries[i])
			}
			ver.list = peArray(elements)
		}
		return ver.list
	}
	return ModuleValue{}
}

func peVersionListEntryFields(entry peVersionEntry) ModuleValue {
	return peLazyStruct(func(name string) ModuleValue {
		switch name {
		case "key":
			return StringValue(entry.key)
		case "value":
			return StringValue(entry.value)
		}
		return ModuleValue{}
	})
}

// peVersionString converts a UTF-8 string decoded by go-pe into libyara's
// bounded low-byte UTF-16LE projection (strlcpy_w), capping at maxUnits bytes
// and stopping at the first UTF-16 code unit whose low byte is zero.
func peVersionString(s string, maxUnits int) string {
	fast := true
	for i := 0; i < len(s); i++ {
		if s[i] == 0 || s[i] >= 0x80 {
			fast = false
			break
		}
	}
	if fast {
		if len(s) > maxUnits {
			return s[:maxUnits]
		}
		return s
	}
	units := utf16.Encode([]rune(s))
	limit := min(len(units), maxUnits)
	buf := make([]byte, 0, limit)
	for _, u := range units[:limit] {
		low := byte(u) //checkednarrow:ignore libyara strlcpy_w preserves low byte of UTF-16 unit
		if low == 0 {
			break
		}
		buf = append(buf, low)
	}
	return string(buf)
}
