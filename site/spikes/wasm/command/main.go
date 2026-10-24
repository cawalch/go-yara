package main

import (
	"fmt"
	"github.com/cawalch/go-yara/site/spikes/wasm/engine"
	"log"
)

func main() {
	n, err := engine.Check()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PASS: %d fixtures, three scans per valid rule set\n", n)
}
