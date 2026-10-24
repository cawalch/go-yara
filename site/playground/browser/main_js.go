//go:build js && wasm

package main

import (
	"runtime/debug"
	"syscall/js"

	"github.com/cawalch/go-yara/site/playground/engine"
)

func main() {
	debug.SetMemoryLimit(engine.Limits.HeapBytes)
	call := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 3 || args[2].Type() != js.TypeBoolean {
			return engine.Encode(engine.Reply{Error: "Invalid scan request."})
		}
		rules := args[0].String()
		if len(rules) > engine.Limits.RulesBytes {
			return engine.Encode(engine.Reply{Error: "Rule source exceeds 16 KiB."})
		}
		n := args[1].Get("byteLength").Int()
		if n > engine.Limits.InputBytes {
			return engine.Encode(engine.Reply{Error: "Input exceeds 1 MiB."})
		}
		data := make([]byte, n)
		js.CopyBytesToGo(data, args[1])
		return engine.Encode(engine.Scan(rules, data, args[2].Bool()))
	})
	js.Global().Set("goYaraRun", call)
	js.Global().Call("goYaraReady")
	select {}
}
