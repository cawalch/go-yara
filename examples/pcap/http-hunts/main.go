// Command http-hunts evaluates the example inventory and rules on a cleartext capture.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"

	pcap "github.com/cawalch/go-pcap"

	"github.com/cawalch/go-yara/compiler"
)

//go:embed requests.yar
var rules string

// These facts apply to the synthetic capture's client-facing observation point.
// Approval here covers only webhook.site or the app.example decoy, respectively.
type sourcePolicy struct {
	restricted, webhookApproved, scannerApproved bool
}

var inventory = map[netip.Addr]sourcePolicy{
	netip.MustParseAddr("192.0.2.10"): {restricted: true},
	netip.MustParseAddr("192.0.2.11"): {restricted: true, webhookApproved: true},
	netip.MustParseAddr("192.0.2.12"): {},
	netip.MustParseAddr("192.0.2.13"): {scannerApproved: true},
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: http-hunts capture.pcap[ng]")
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
	requests, err := c.HTTPRequestsFromReaderAt(f)
	if err != nil {
		return err
	}
	return report(requests, out)
}

func report(requests []pcap.HTTPRequestObservation, out io.Writer) error {
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), rules)
	if err != nil {
		return err
	}
	scanner := program.NewScanner()
	defer scanner.Close()
	for _, r := range requests {
		policy, known := inventory[r.Source.Addr()]
		if !known {
			continue
		}
		authority, err := url.Parse("//" + r.Authority)
		if err != nil || authority.User != nil || authority.Host != r.Authority {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(authority.Hostname(), "."))
		path, _, _ := strings.Cut(r.Path, "?")
		if err := scanner.SetExternalVariables(map[string]any{
			"destination_host": host, "http_method": r.Method,
			"restricted_server": policy.restricted, "approved_webhook": policy.webhookApproved,
			"approved_scanner": policy.scannerApproved, "decoy_route": host == "app.example" && path == "/unused-canary",
		}); err != nil {
			return err
		}
		result, err := scanner.Scan(nil)
		if err != nil {
			return err
		}
		for _, match := range result.MatchedRules {
			if _, err := fmt.Fprintf(out, "%s frame=%d time_ns=%d flow=%d stream=%d source=%s %s %s\n",
				match.Rule, r.PacketIndex+1, r.TimestampNs, r.FlowIndex, r.StreamID, r.Source.Addr(), r.Method, host); err != nil {
				return err
			}
		}
	}
	return nil
}
