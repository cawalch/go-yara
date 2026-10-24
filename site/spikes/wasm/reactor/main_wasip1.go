//go:build wasip1 && wasm

package main

import "github.com/cawalch/go-yara/site/spikes/wasm/engine"

// This export only establishes reactor feasibility. It is not a host ABI.
//
//go:wasmexport check
//nolint:unused // Called by the Wasm host through this export.
func check() int32 {
	n, err := engine.Check()
	if err != nil {
		return -1
	}
	return int32(n)
}

func main() {}
