//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/cawalch/go-yara/site/spikes/wasm/engine"
)

func main() {
	session := new(engine.Session)
	call := js.FuncOf(func(_ js.Value, args []js.Value) any {
		var reply engine.Reply
		if len(args) != 2 {
			reply.Error = "expected operation and value"
		} else {
			switch args[0].String() {
			case "compile":
				reply = session.Compile(args[1].String())
			case "scan":
				n := args[1].Get("byteLength").Int()
				if n > engine.MaxInput {
					reply.Error = "input exceeds 8 MiB"
					break
				}
				data := make([]byte, n)
				js.CopyBytesToGo(data, args[1])
				reply = session.Scan(data)
			default:
				reply.Error = "unknown operation"
			}
		}
		encoded, _ := json.Marshal(reply)
		return string(encoded)
	})
	js.Global().Set("goYaraCall", call)
	js.Global().Call("goYaraReady")
	select {}
}
