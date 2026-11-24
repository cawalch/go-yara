package httphunts

import (
	_ "embed"
	"testing"

	pcap "github.com/cawalch/go-pcap"

	"github.com/cawalch/go-yara/compiler"
)

//go:embed requests.yar
var rules string

func TestCaptureHunts(t *testing.T) {
	p, err := compiler.NewCompiler().CompileSourceWithContext(t.Context(), rules)
	if err != nil {
		t.Fatal(err)
	}
	scanner := p.NewScanner()
	defer scanner.Close()
	cases := []struct {
		name, host, method, path                       string
		restricted, approvedCollector, approvedScanner bool
		want                                           string
	}{
		{"unexpected collector POST", "WEBHOOK.SITE", "POST", "/example", true, false, false, "unexpected_server_webhook_post"},
		{"approved integration", "webhook.site", "POST", "/example", true, true, false, ""},
		{"developer workstation", "webhook.site", "POST", "/example", false, false, false, ""},
		{"similar destination", "webhook.site.example", "POST", "/example", true, false, false, ""},
		{"ordinary GET", "webhook.site", "GET", "/example", true, false, false, ""},
		{"private decoy", "app.example", "GET", "/unused-canary", false, false, false, "unapproved_decoy_route_access"},
		{"approved scanner", "app.example", "GET", "/unused-canary", false, false, true, ""},
		{"ordinary route", "app.example", "GET", "/health", false, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.method + " " + tc.path + " HTTP/1.1\r\nHost: " + tc.host + "\r\nContent-Length: 0\r\n\r\n"
			req, _, err := pcap.ParseHTTPRequest([]byte(wire))
			if err != nil {
				t.Fatal(err)
			}
			vars := map[string]any{"destination_host": req.Host, "http_method": req.Method, "restricted_server": tc.restricted,
				"approved_webhook": tc.approvedCollector, "approved_scanner": tc.approvedScanner,
				"decoy_route": req.Host == "app.example" && req.Path == "/unused-canary"}
			if err := scanner.SetExternalVariables(vars); err != nil {
				t.Fatal(err)
			}
			result, err := scanner.Scan(nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range []string{"unexpected_server_webhook_post", "unapproved_decoy_route_access"} {
				if result.RuleResults[rule] != (tc.want == rule) {
					t.Fatalf("%s: got %v, want %q", rule, result.RuleResults, tc.want)
				}
			}
		})
	}
}
