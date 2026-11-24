# Detecting network activity with go-pcap and go-yara

Use the built-in `pcap` module to evaluate TLS certificate names across a
capture. For other protocol fields, a Go application can decode records with
go-pcap and pass the field of interest to a YARA rule. The DNS example below
shows how to carry the matching packet and flow into a finding.

For web investigations, see [hunting ARTEX-like activity in captured HTTP](http-capture-hunts.md)
for tested rules covering unexpected webhook uploads and private decoy routes.

Run these examples from a go-yara checkout containing the pilot (commit
`0871b5b` or later). The published v0.11.1 CLI predates `import "pcap"`.
The commands use synthetic PcapNG fixtures from the pinned go-pcap dependency.

## Triage a certificate-name alert after a proxy change

After a proxy or load-balancer certificate rotation, a listener might present
its default certificate for the wrong hostname. The [TLS rules](../examples/pcap/tls.yar)
compare each observed ClientHello server name (SNI) with the DNS names on the
server leaf certificate for that same flow.

```sh
go mod download github.com/cawalch/go-pcap
fixtures="$(go list -m -f '{{.Dir}}' github.com/cawalch/go-pcap)/testdata/deployments"
go run ./cmd examples/pcap/tls.yar "$fixtures/proxy.pcapng"
```

The CLI prints the rule name followed by the input path. On the proxy fixture
the only hit is `tls_name_evidence_missing`. Both proxy legs have a TLS 1.3
handshake, but the capture has no keys to recover either leaf certificate.
On a capture with visible certificates, `tls_name_mismatch` fires if any flow
has a **defined false** comparison. Check which proxy leg presented the
certificate and whether its configured SANs cover the requested hostname.

| `row.server_name_match` | Example |
| --- | --- |
| `true` | The SNI is `api.example.test` and the leaf includes `*.example.test`. |
| `false` | The SNI is `api.example.test` and the complete leaf DNS SAN list contains only `other.example.test`. |
| undefined | The server leaf is unavailable, the SNI is missing or unusable, or a matching SAN may have been omitted at the parser limit. |

Each row has a zero-based integer `flow_index` assigned by go-pcap across the capture.
Flows without a TLS handshake can precede it. For example, a rule can require
`row.flow_index == 3` alongside its name check. A rule match identifies the
rule and input. The comparison alone makes no assertion about certificate trust
or malicious activity.

To reproduce a confirmed mismatch, run the integration test. Its synthetic
capture includes a wildcard match, a mismatch on flow 2, a missing leaf,
and a name beyond the SAN limit. It exercises both slice and seekable inputs.

```sh
go test ./compiler -run '^TestPCAP(Example|Name)Rules$' -v
```

## Identify devices querying a watched DNS name

During a collector migration, you may want to find devices still querying the
old hostname. The [DNS watch example](../examples/pcap/dns-watch/main.go)
uses go-pcap to decode questions, skips responses, and scans each question name
with a compiled YARA rule. The rule matches the complete name case-insensitively.
The application retains the packet and flow indices from that DNS record.

```sh
go run ./examples/pcap/dns-watch "$fixtures/iot.pcapng"
```

```text
watched_dns_question packet=2 flow=2 name="collector.example"
```

The indices are zero-based, so open frame 3 in a packet viewer. The same command
on `client.pcapng` produces no output because its question is for `trace.example`.
A hit establishes that the device queried the name. A completed connection or
successful migration requires separate evidence.

## Investigate a required service that fails to resolve

Run this command from the **go-yara** repository root. It uses the example’s
synthetic capture and the [required-service rule](../examples/pcap/dns-failure/required-service.yar).

```sh
go run ./examples/pcap/dns-failure ./examples/pcap/dns-failure/testdata/service.pcap
```

```text
required_service_dns_failure name="api.example" resolver=192.0.2.53:53 rcode=3 query_frame=1 reply_frame=2
required_service_dns_failure name="api.example" resolver=192.0.2.53:53 rcode=2 query_frame=3 reply_frame=4
```

Open frame 2 in Wireshark for the NXDOMAIN reply (name does not exist) and
frame 4 for SERVFAIL (resolver failed to complete the lookup). To check another
service, edit `$service` in the rule and rerun with your capture path.

The [Go adapter](../examples/pcap/dns-failure/main.go) pairs ordinary
single-question DNS on port 53 by flow, directional endpoints, ID, and decoded
question. It gives YARA the complete name as input and the DNS response code
as an external integer. Use a capture from one observation point. Repeated
identical outstanding questions make that key ambiguous for the rest of the
capture. The fixture includes a healthy reply, another service, an unanswered
query, an orphan reply, an ambiguous retry, and an extended response code.
Only the two paired failures above produce findings.

## Capture and reader limits

The scanner opens the capture and extracts TLS on first evaluated access to `pcap.tls`, then
reuses the results across rules in that scan. Importing the module or testing `defined pcap` alone incurs
zero TLS scans. A valid capture without TLS yields an empty array. Malformed
input, parser errors and inputs larger than 64 MiB make `pcap.tls` undefined.
Go-pcap can use secrets embedded in PcapNG to recover a TLS 1.3 certificate.

For slice scans, pass the complete capture. For streaming scans, pass a reader
that implements both `io.ReaderAt` and `io.Seeker` (such as an open file or
`bytes.Reader`). Offsets are relative to the starting stream position. For a
sequential-only reader the complete capture must fit in the retained 64 KiB
header. A partial capture prefix cannot supply TLS evidence.
