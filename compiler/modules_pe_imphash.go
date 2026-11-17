package compiler

import (
	"crypto/md5" // #nosec G501 -- YARA compatibility requires MD5.
	"encoding/hex"
	"hash"
	"strings"

	pe "github.com/cawalch/go-pe"
)

// peImphash implements libyara's pe.imphash(). It hashes the already-filtered
// standard-import records in descriptor order, using the frozen ordinal names
// from libyara's ord_lookup rather than display-name synthesis.
func (i *Interpreter) peImphash() ModuleValue {
	if i.currentCompiledRule == nil || !i.currentCompiledRule.nativePE {
		return ModuleValue{}
	}
	done := peCancelDone(i.matchContext)
	if scanCanceled(done) {
		return ModuleValue{}
	}
	if data, supplied := i.moduleData["pe"]; supplied {
		return peHostImphash(data, done)
	}
	image := loadPE(i.matchContext)
	if image.file == nil {
		return ModuleValue{}
	}
	imports := image.loadImports()
	if !imports.valid {
		return ModuleValue{}
	}
	hash, ok := peImphashLibrariesWithCancel(imports.libraries, done)
	if !ok {
		return ModuleValue{}
	}
	return StringValue(hash)
}

// Host snapshots take precedence over file parsing. An absent import_details
// array leaves the hash undefined; an empty array hashes as an empty sequence.
func peHostImphash(data ModuleValue, done <-chan struct{}) ModuleValue {
	if data.object == nil {
		return ModuleValue{}
	}
	details, exists := data.object.fields["import_details"]
	if !exists || details.object == nil {
		return ModuleValue{}
	}
	builder := newPEImphashBuilder()
	seen := 0
	for _, library := range details.object.elements {
		if library.object == nil {
			continue
		}
		libraryName := library.object.fields["library_name"]
		if libraryName.Type != ModuleString {
			continue
		}
		dll := peCString(libraryName.String)
		hashName := peImphashLibraryName(dll)
		kind := peMatchOrdinalDLL(dll)
		functions := library.object.fields["functions"]
		if functions.object == nil {
			continue
		}
		for _, symbol := range functions.object.elements {
			if scanCanceledAt(done, seen) {
				return ModuleValue{}
			}
			seen++
			if symbol.object == nil {
				continue
			}
			ordinal := symbol.object.fields["ordinal"]
			var functionName string
			if ordinal.Type == ModuleInteger {
				if ordinal.Integer < 0 || ordinal.Integer > 65535 {
					continue
				}
				functionName = peImportOrdinalName(kind, uint16(ordinal.Integer)) //checkednarrow:ignore range checked above
			} else {
				name := symbol.object.fields["name"]
				if name.Type != ModuleString {
					continue
				}
				functionName = peCString(name.String)
			}
			builder.add(hashName, functionName)
		}
	}
	return StringValue(builder.sum())
}

func peImphashLibraries(libraries []pe.ImportLibrary) string {
	sum, _ := peImphashLibrariesWithCancel(libraries, nil)
	return sum
}

func peImphashLibrariesWithCancel(libraries []pe.ImportLibrary, done <-chan struct{}) (string, bool) {
	builder := newPEImphashBuilder()
	seen := 0
	for i := range libraries {
		library := &libraries[i]
		dll := peCString(library.DLL)
		libraryName := peImphashLibraryName(dll)
		kind := peMatchOrdinalDLL(dll)
		for j := range library.Symbols {
			if scanCanceledAt(done, seen) {
				return "", false
			}
			seen++
			symbol := &library.Symbols[j]
			functionName := peCString(symbol.Name)
			if symbol.ByOrdinal {
				functionName = peImportOrdinalName(kind, symbol.Ordinal)
			}
			builder.add(libraryName, functionName)
		}
	}
	return builder.sum(), true
}

type peImphashBuilder struct {
	digest  hash.Hash
	scratch [256]byte
	first   bool
}

func newPEImphashBuilder() *peImphashBuilder {
	return &peImphashBuilder{digest: md5.New(), first: true} // #nosec G401 -- YARA compatibility requires MD5.
}

func (builder *peImphashBuilder) add(library, function string) {
	if !builder.first {
		builder.writeByte(',')
	}
	builder.writeLower(library)
	builder.writeByte('.')
	builder.writeLower(function)
	builder.first = false
}

func (builder *peImphashBuilder) sum() string {
	return hex.EncodeToString(builder.digest.Sum(nil))
}

func (builder *peImphashBuilder) writeByte(character byte) {
	builder.scratch[0] = character
	_, _ = builder.digest.Write(builder.scratch[:1])
}

// writeLower streams ASCII lowercase bytes through builder-owned scratch
// storage without allocating a joined import string. libyara lowercases with
// C-locale tolower.
func (builder *peImphashBuilder) writeLower(value string) {
	for len(value) > 0 {
		n := min(len(value), len(builder.scratch))
		for i := range n {
			character := value[i]
			if character >= 'A' && character <= 'Z' {
				character += 'a' - 'A'
			}
			builder.scratch[i] = character
		}
		_, _ = builder.digest.Write(builder.scratch[:n])
		value = value[n:]
	}
}

func peCString(value string) string {
	if before, _, ok := strings.Cut(value, "\x00"); ok {
		return before
	}
	return value
}

// libyara uses strrchr plus a four-byte strncasecmp, so extensions such as
// ".dllx" are stripped just like ".dll".
func peImphashLibraryName(name string) string {
	last := strings.LastIndexByte(name, '.')
	if last < 0 || len(name)-last < 4 {
		return name
	}
	extension := name[last : last+4]
	if peNameEqual(extension, ".ocx") || peNameEqual(extension, ".sys") || peNameEqual(extension, ".dll") {
		return name[:last]
	}
	return name
}
