# Detecting network activity with go-pcap and go-yara

Use the built-in `pcap` module to evaluate cleartext HTTP/1 transactions,
unicast DNS exchanges, and TLS certificate-name evidence in a capture.
[Compare an update rule revision](#review-an-update-detection-rule) using two
synthetic captures. The docs site runs the same rules in a local Wasm worker.

Use a current go-yara source checkout for the CLI commands. The published
v0.11.1 CLI predates `import "pcap"`. The TLS examples use synthetic PcapNG
fixtures from the pinned go-pcap dependency.

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

## Classify TLS evidence across the capture

The [TLS triage rules](../examples/pcap/tls-triage.yar) use only `import "pcap"`:

| Rule | Capture evidence required |
| --- | --- |
| `tls_multiple_name_mismatches` | At least two TLS rows with defined false comparisons. |
| `tls_mixed_name_results` | At least one agreement and one defined mismatch. |
| `tls_mismatch_with_evidence_gaps` | A defined mismatch and a separate undefined comparison. |
| `tls_all_observed_names_match` | At least one TLS row, with every row defined and matching. |

```sh
go run ./cmd examples/pcap/tls-triage.yar "$fixtures/proxy.pcapng"
go test ./compiler -run '^TestPCAPTriageRules$' -v
```

The proxy fixture produces no triage matches: missing leaf certificates leave
all comparisons undefined. Tests cover positive findings, missing-only evidence,
empty TLS collections, malformed input, scanner reuse, slice/ReaderAt parity,
and serialized rules. `for 2` is an at-least threshold; `for all` needs an
existence guard because an empty collection satisfies universal quantification.

These are capture-wide observations. The TLS collection exposes
`flow_index` and `server_name_match`, so mixed results cannot establish a common
hostname, listener, or time window. Name agreement does not establish trust,
and an undefined comparison is never positive mismatch evidence.

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
input and parser errors make `pcap.tls` undefined. Go-pcap can use secrets
embedded in PcapNG to recover a TLS 1.3 certificate.

Pass a complete capture of at most 64 MiB to a slice scan, including the
default CLI path. To scan a larger capture, use `ScanReader` with a reader
that implements `io.ReaderAt` and `io.Seeker`, such as an open file. Go-pcap
limits protocol scan reads to 64 MiB. Exceeding its read budget leaves
`pcap.tls` undefined. Offsets are relative to the starting stream position.
For a sequential-only reader the complete capture must fit in the retained
64 KiB header.

## Review an update detection rule

Run the baseline and candidate against the same inputs.

```sh
fixture=examples/pcap/update-review
go run ./cmd/compare -baseline "$fixture/baseline.yar" -candidate "$fixture/candidate.yar" \
  positive="$fixture/positive.pcap" control="$fixture/control.pcap"
```

The control removes `revoked_update`. Both revisions match the positive capture.
The candidate checks the request target and the complete response body in one
HTTP/1 transaction. The fixtures contain synthetic build identifiers. Pass `-externals bindings.json`
to apply the same declared values to both scanners. The report lists binding names.

`pcap.http` exposes endpoint addresses and ports, `flow_index`, `method`,
`target`, `authority`, `pairing`, `status`, `request_headers`, `response_headers`,
`request_body`, `response_body`, and their corresponding `*_body_state` fields.
Pairing is `confirmed`, `ambiguous`, or `unseen`. A body can be `complete`,
`partial`, `unknown`, or `unsupported`. The last two states leave body bytes
undefined. Header rows preserve the name, raw value, and wire order.
`request_packet`, `request_offset`, `response_packet`, and `packets` locate
the original HTTP evidence. Timestamps are in nanoseconds when available.

`pcap.dns` exposes standard unicast port-53 exchanges. `pairing` is `paired`,
`no_reply_observed`, `no_query_observed`, `ambiguous`, or `unsupported`.
Each observed `query` and `reply` has `id`, `rcode`, endpoint addresses and
ports, `flow_index`, `packet_index`, `timestamp_ns`, `questions`, `answers`,
declared counts, and `complete`. Answer rows expose addresses and CNAME targets
when available. Flow indices identify transport observations. Use endpoints,
capture scope and time when relating DNS to HTTP.

Collections are evaluated lazily and cached per scan. An unavailable collection
is undefined. `pcap.capture_truncated` reports a clipped container tail. A
complete DNS record describes the observed message; a complete HTTP body
describes the observed entity. Use packet locations to inspect the
observation point and original capture.
