// Command dns-watch checks decoded DNS questions against one inventory name.
package main

import (
	"context"
	"fmt"
	"os"

	pcap "github.com/cawalch/go-pcap"

	"github.com/cawalch/go-yara/compiler"
)

const rule = `rule watched_dns_question {
    strings:
        $name = "collector.example" nocase
    condition:
        $name at 0 and !name[1] == filesize
}`

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dns-watch capture.pcapng")
		os.Exit(2)
	}
	if err := scan(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func scan(path string) error {
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
	records, err := capture.DNSFromReaderAt(file)
	if err != nil {
		return err
	}
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), rule)
	if err != nil {
		return err
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	for _, record := range records {
		if record.Message.IsResponse {
			continue
		}
		for _, q := range record.Message.Questions {
			result, err := scanner.Scan([]byte(q.Name))
			if err != nil {
				return err
			}
			if result.RuleResults["watched_dns_question"] {
				fmt.Printf("watched_dns_question packet=%d flow=%d name=%q\n", record.PacketIndex, record.FlowIndex, q.Name)
			}
		}
	}
	return nil
}
