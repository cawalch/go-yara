package compiler

import (
	"maps"

	pe "github.com/cawalch/go-pe"
)

func newPEExportsSchema() *ModuleSchema {
	fields := maps.Clone(peImportsSchema.Fields)
	fields["number_of_exports"] = ModuleField{Kind: ModuleInteger}
	fields["export_details"] = ModuleField{Kind: ModuleArray, Element: &ModuleField{Kind: ModuleStruct,
		Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"ordinal": {Kind: ModuleInteger}, "rva": {Kind: ModuleInteger}, "offset": {Kind: ModuleInteger},
			"name": {Kind: ModuleString}, "forward_name": {Kind: ModuleString},
		}},
	}}
	return &ModuleSchema{Fields: fields}
}

func newPEExportTimestampSchema() *ModuleSchema {
	fields := maps.Clone(peExportsSchema.Fields)
	fields["export_timestamp"] = ModuleField{Kind: ModuleInteger}
	return &ModuleSchema{Fields: fields}
}

// A non-nil cache records success or failure independently of import parsing.
// go-pe owns parsing limits; the adapter limits exposure to libyara's 16,384 slots.
type peExportData struct {
	symbols   []pe.ExportSymbol
	details   ModuleValue
	fileSize  int64
	timestamp uint32
	valid     bool
	present   bool // A missing directory has no timestamp; zero is a valid timestamp.
}

func (image *peImage) loadExports() *peExportData {
	if image.exports == nil {
		image.exports = &peExportData{fileSize: image.context.FileSize}
		directory, err := image.file.Exports(peScanData(image.context))
		if err == nil {
			image.exports.valid = true
			if directory != nil {
				image.exports.present = true
				image.exports.timestamp = directory.TimeDateStamp
				image.exports.symbols = directory.Symbols[:min(len(directory.Symbols), 16384)]
			}
		}
	}
	return image.exports
}

func (image *peImage) exportField(name string) ModuleValue {
	exports := image.loadExports()
	if !exports.valid {
		return ModuleValue{}
	}
	if name == "number_of_exports" {
		return IntegerValue(int64(len(exports.symbols)))
	}
	if name == "export_timestamp" {
		if exports.present {
			return IntegerValue(int64(exports.timestamp))
		}
		return ModuleValue{}
	}
	if exports.details.Type == ModuleUndefined {
		values := make([]ModuleValue, len(exports.symbols))
		for i := range values {
			values[i] = peExportFields(&exports.symbols[i], image.file, exports.fileSize)
		}
		exports.details = peArray(values)
	}
	return exports.details
}

func peExportFields(symbol *pe.ExportSymbol, file *pe.File, fileSize int64) ModuleValue {
	return peLazyStruct(func(name string) ModuleValue {
		switch name {
		case "ordinal":
			return IntegerValue(int64(symbol.Ordinal))
		case "rva":
			return IntegerValue(int64(symbol.RVA))
		case "name":
			if len(symbol.Names) != 0 {
				return StringValue(symbol.Names[0][:min(len(symbol.Names[0]), 512)])
			}
		case "forward_name":
			if symbol.Forwarded {
				return StringValue(symbol.Forwarder[:min(len(symbol.Forwarder), 512)])
			}
		case "offset":
			if !symbol.Forwarded {
				if offset := peRVAToOffset(file, symbol.RVA, fileSize); offset >= 0 {
					return IntegerValue(offset)
				}
			}
		}
		return ModuleValue{}
	})
}
