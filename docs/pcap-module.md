# TLS certificate-name rules for captures

Import `pcap` to inspect TLS handshakes in a classic PCAP or PcapNG capture.
This rule flags a capture when at least one observed client DNS name disagrees
with the DNS names on that flow’s server leaf certificate.

```yara
import "pcap"

rule tls_name_mismatch {
    condition:
        for any row in pcap.tls : (
            defined row.server_name_match and not row.server_name_match
        )
}
```

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

The scanner opens the capture and extracts TLS on first evaluated access, then
reuses the results across rules in that scan. Importing the module alone incurs
zero TLS scans. A valid capture without TLS yields an empty array. Malformed
input, parser errors and inputs larger than 64 MiB yield undefined module data.
Go-pcap can use secrets embedded in PcapNG to recover a TLS 1.3 certificate.

For slice scans, pass the complete capture. For streaming scans, pass a reader
that implements both `io.ReaderAt` and `io.Seeker` (such as an open file or
`bytes.Reader`). Offsets are relative to the starting stream position. For a
sequential-only reader the complete capture must fit in the retained 64 KiB
header. A partial capture prefix cannot supply TLS evidence.
