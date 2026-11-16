// This build-time probe exports the registered module signatures and format.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/cawalch/go-yara/compiler"
)

type entry struct {
	Name       string   `json:"name"`
	Signatures []string `json:"signatures"`
	Cacheable  bool     `json:"cacheable"`
}

func main() {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), `
import "hash" import "math" import "string" import "time"
rule catalog {
	condition:
		hash.checksum32("a") >= 0 and
		hash.crc32("a") >= 0 and
		hash.md5("a") != "" and
		hash.sha1("a") != "" and
		hash.sha256("a") != "" and
		hash.sha512("a") != "" and
		math.abs(1) >= 0 and
		math.count(1) >= 0 and
		math.deviation(0, 1) >= 0.0 and
		math.entropy("a") >= 0.0 and
		math.in_range(0.5, 0.0, 1.0) >= 0 and
		math.max(1, 2) >= 0 and
		math.mean("a") >= 0.0 and
		math.min(1, 2) >= 0 and
		math.mode() >= 0 and
		math.monte_carlo_pi("a") >= 0.0 and
		math.percentage(1) >= 0.0 and
		math.serial_correlation("a") >= 0.0 and
		math.to_number(true) >= 0 and
		math.to_string(1) != "" and
		string.length("a") >= 0 and
		string.to_int("1") >= 0 and
		time.now() >= 0
}`)
	if err != nil {
		log.Fatal(err)
	}
	encoded, err := program.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	types := map[compiler.ModuleValueType]string{
		compiler.ModuleInteger: "integer", compiler.ModuleFloat: "float",
		compiler.ModuleString: "string", compiler.ModuleBoolean: "boolean",
	}
	entries := []entry{}
	rule := program.Rules[0]
	for id, function := range rule.ModuleFunctions {
		item := entry{Name: rule.ModuleNames[id], Cacheable: function.Cacheable}
		for _, signature := range function.Signatures {
			var args []string
			for _, argument := range signature.Arguments {
				args = append(args, types[argument])
			}
			result := signature.ReturnType
			if result == compiler.ModuleUndefined {
				result = function.ReturnType
			}
			item.Signatures = append(item.Signatures, "("+strings.Join(args, ", ")+") → "+types[result])
		}
		entries = append(entries, item)
	}
	if len(entries) == 0 {
		log.Fatal("catalog compiled zero module entries")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"format": binary.BigEndian.Uint16(encoded[7:9]), "modules": entries,
	}); err != nil {
		log.Fatal(err)
	}
}
