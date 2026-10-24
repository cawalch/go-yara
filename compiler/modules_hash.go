package compiler

import (
	"crypto/md5"  // #nosec G501 -- YARA compatibility requires MD5.
	"crypto/sha1" // #nosec G505 -- YARA compatibility requires SHA-1.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash/crc32"
)

func hashModule() Module {
	functions := make(map[string]ModuleFunction)
	for name, eval := range map[string]func([]byte) ModuleValue{
		"md5":  func(data []byte) ModuleValue { sum := md5.Sum(data); return StringValue(hex.EncodeToString(sum[:])) },  // #nosec G401 -- YARA compatibility requires MD5.
		"sha1": func(data []byte) ModuleValue { sum := sha1.Sum(data); return StringValue(hex.EncodeToString(sum[:])) }, // #nosec G401 -- YARA compatibility requires SHA-1.
		"sha256": func(data []byte) ModuleValue {
			sum := sha256.Sum256(data)
			return StringValue(hex.EncodeToString(sum[:]))
		},
		"sha512": func(data []byte) ModuleValue {
			sum := sha512.Sum512(data)
			return StringValue(hex.EncodeToString(sum[:]))
		},
		"crc32": func(data []byte) ModuleValue { return IntegerValue(int64(crc32.ChecksumIEEE(data))) },
		"checksum32": func(data []byte) ModuleValue {
			var sum uint32
			for _, b := range data {
				sum += uint32(b)
			}
			return IntegerValue(int64(sum))
		},
	} {
		resultType := ModuleString
		if name == "crc32" || name == "checksum32" {
			resultType = ModuleInteger
		}
		functions[name] = dataModuleFunction(resultType, eval)
	}
	return Module{Name: "hash", Functions: functions}
}

func dataModuleFunction(resultType ModuleValueType, eval func([]byte) ModuleValue) ModuleFunction {
	return ModuleFunction{
		Signatures: stringAndRangeSignatures(),
		ReturnType: resultType, Cacheable: true,
		Evaluate: func(ctx ModuleContext, args []ModuleValue) (ModuleValue, error) {
			data, ok := moduleDataRange(ctx, args)
			if !ok {
				return ModuleValue{}, nil
			}
			return eval(data), nil
		},
	}
}

// moduleDataRange follows YARA's range rules: a range must start inside a
// block, may extend past EOF, and cannot cross a gap between blocks.
func moduleDataRange(ctx ModuleContext, args []ModuleValue) ([]byte, bool) {
	if len(args) == 1 && args[0].Type == ModuleString {
		return []byte(args[0].String), true
	}
	if len(args) != 2 || args[0].Type != ModuleInteger || args[1].Type != ModuleInteger {
		return nil, false
	}
	offset, size := args[0].Integer, args[1].Integer
	if offset < 0 || size < 0 {
		return nil, false
	}
	if ctx.Data != nil {
		if offset >= int64(len(ctx.Data)) {
			return nil, false
		}
		return ctx.Data[offset : offset+min(size, int64(len(ctx.Data))-offset)], true
	}
	var data []byte
	started, owned := false, false
	for _, block := range ctx.Blocks {
		relative := offset - block.Base
		if relative < 0 || relative >= int64(len(block.Data)) {
			if started {
				return nil, false
			}
			continue
		}
		count := min(size, int64(len(block.Data))-relative)
		part := block.Data[relative : relative+count]
		if !started {
			data = part
		} else {
			// Copy once before growing across blocks; never append into caller
			// capacity, and avoid quadratic copying across many small blocks.
			if !owned {
				joined := make([]byte, len(data), len(data)+len(part))
				copy(joined, data)
				data, owned = joined, true
			}
			data = append(data, part...)
		}
		started = true
		offset += count
		size -= count
		if size == 0 {
			break
		}
	}
	return data, started
}

func stringAndRangeSignatures() []ModuleSignature {
	return []ModuleSignature{{Arguments: []ModuleValueType{ModuleString}}, {Arguments: []ModuleValueType{ModuleInteger, ModuleInteger}}}
}
