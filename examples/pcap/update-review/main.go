package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"os"

	pcap "github.com/cawalch/go-pcap"

	"github.com/cawalch/go-yara/compiler"
)

//go:embed entity.yar
var rules string

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: go run ./examples/pcap/update-review capture.pcap")
	}
	if err := inspect(context.Background(), os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func inspect(ctx context.Context, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	capture, err := pcap.NewFromReaderAt(file, info.Size())
	if err != nil {
		return err
	}
	transactions, err := capture.HTTP1TransactionsFromReaderAt(file)
	if err != nil {
		return err
	}
	program, err := compiler.NewCompiler().CompileSourceWithContext(ctx, rules)
	if err != nil {
		return err
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	for _, tx := range transactions {
		scan, err := scanner.ScanHTTP1Response(ctx, tx.ResponseArtifact())
		if err != nil {
			return err
		}
		artifact := scan.Artifact
		fmt.Printf("%s bytes=%d ", tx.Request.Target, len(artifact.Body))
		switch {
		case scan.Result != nil && len(scan.Result.MatchedRules) > 0:
			for _, rule := range scan.Result.MatchedRules {
				for _, hit := range rule.Matches["$id"] {
					fmt.Printf("rule=%s entity_offset=%d response_packet=%d\n",
						rule.Rule, hit.Offset, artifact.ResponsePacketIndex)
				}
			}
		case scan.Result != nil:
			fmt.Println("inspected, no match")
		case artifact.Coverage == pcap.HTTP1ArtifactPartial:
			fmt.Println("partial, skipped")
		default:
			fmt.Println("unavailable, skipped")
		}
	}
	return nil
}
