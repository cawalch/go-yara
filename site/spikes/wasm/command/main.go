package main

import (
	"fmt"
	"log"

	"github.com/cawalch/go-yara/site/spikes/wasm/engine"
)

func main() {
	n, err := engine.Check()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PASS: %d fixtures, three scans per valid rule set\n", n)
}
