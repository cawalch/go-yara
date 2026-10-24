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
rule catalog { condition: true }`)
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
	var entries []entry
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
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"format": binary.BigEndian.Uint16(encoded[7:9]), "modules": entries,
	}); err != nil {
		log.Fatal(err)
	}
}
