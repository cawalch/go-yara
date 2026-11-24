// Command dns-failure applies a YARA rule to paired DNS questions and replies.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	pcap "github.com/cawalch/go-pcap"

	"github.com/cawalch/go-yara/compiler"
)

//go:embed required-service.yar
var rule string

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dns-failure capture.pcap[ng]")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	c, err := pcap.NewFromReaderAt(f, info.Size())
	if err != nil {
		return err
	}
	rows, err := c.DNSFromReaderAt(f)
	if err != nil {
		return err
	}
	return report(rows, out)
}

type queryKey struct {
	flow             int
	client, resolver netip.AddrPort
	id               uint16
	question         pcap.DNSQuestion
}

func report(rows []pcap.DNSRecord, out io.Writer) error {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), rule)
	if err != nil {
		return err
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	// Positive values are one-based query frames. An overlapping identical
	// query leaves the key ambiguous for the rest of this capture.
	pending := make(map[queryKey]int)
	for _, r := range rows {
		m := r.Message
		if m.Opcode != 0 || m.QuestionCount != 1 || len(m.Questions) != 1 || m.Anomalies.Any() {
			continue
		}
		client := netip.AddrPortFrom(r.SrcAddr, r.SrcPort)
		resolver := netip.AddrPortFrom(r.DstAddr, r.DstPort)
		if m.IsResponse {
			client, resolver = resolver, client
		}
		if resolver.Port() != 53 || resolver.Addr().IsMulticast() || client.Addr().IsMulticast() {
			continue
		}
		q := m.Questions[0]
		// Fold only ASCII letters as required for DNS name comparison.
		q.Name = strings.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' {
				return r + ('a' - 'A')
			}
			return r
		}, q.Name)
		key := queryKey{r.FlowIndex, client, resolver, m.TransactionID, q}
		frame, exists := pending[key]
		if !m.IsResponse {
			if exists {
				pending[key] = 0
			} else {
				pending[key] = r.PacketIndex + 1
			}
			continue
		}
		if !exists || frame == 0 {
			continue
		}
		delete(pending, key)
		code := int(m.RCode)
		for _, rr := range m.Additionals {
			if rr.Type == pcap.DNSTypeOPT {
				code |= int(rr.TTL>>24) << 4
			}
		}
		if err := scanner.SetExternalVariables(map[string]any{"dns_rcode": code}); err != nil {
			return err
		}
		matched, err := scanner.Matches([]byte(q.Name))
		if err != nil {
			return err
		}
		if matched {
			if _, err := fmt.Fprintf(out, "required_service_dns_failure name=%q resolver=%s rcode=%d query_frame=%d reply_frame=%d\n", q.Name, resolver, code, frame, r.PacketIndex+1); err != nil {
				return err
			}
		}
	}
	return nil
}
