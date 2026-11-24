# Hunting ARTEX-like activity in captured HTTP

In an ARTEX investigation, Google Threat Intelligence Group observed a database
server sending output to a public webhook collector. Microsoft separately
reported fast, varied web requests during ARTEX activity and described using
decoys to surface unauthorized access. Both behaviors also occur outside an
ARTEX incident. Name a finding after what the capture shows and corroborate it
with endpoint or application logs before attributing it to a tool.
[Google investigation](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)
and [Microsoft investigation, November 6, 2026](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/).

## Two rules to try on decoded requests

| Rule | Required evidence | Benign control |
| --- | --- | --- |
| `unexpected_server_webhook_post` | A visible POST to the exact collector hostname from a server whose inventory role restricts external webhooks. Check the approved integration list for that source and destination. | A registered integration, a developer workstation, or a GET to the same host. |
| `unapproved_decoy_route_access` | A request for a private decoy route on the intended virtual host, from a source outside the approved scanner list. Choose a route absent from normal navigation and logs used by synthetic monitors. | An authorized scanner reaching the decoy, or a request to a normal route. |

From the **go-yara** repository root, scan the synthetic PCAP:

```sh
go run ./examples/pcap/http-hunts ./examples/pcap/http-hunts/testdata/hunts.pcap
```

```text
unexpected_server_webhook_post frame=2 time_ns=1700000000002469134 flow=0 stream=0 source=192.0.2.10 POST webhook.site
unapproved_decoy_route_access frame=11 time_ns=1700000000013580237 flow=5 stream=3 source=192.0.2.12 GET app.example
```

Frame 2 contains the first two bytes of the HTTP/1 POST. Frame 3 completes it.
Frame 11 opens the HTTP/2 HEADERS block on stream 3. Frame 12 completes it.
Each finding reports the starting frame's timestamp in Unix nanoseconds.
Stream zero denotes HTTP/1. The [parity test](../examples/pcap/http-hunts/requests_test.go)
checks the same findings using both the file (ReaderAt) and slice APIs.

The [command](../examples/pcap/http-hunts/main.go) binds the timeline to the
[existing rules](../examples/pcap/http-hunts/requests.yar). Its sample
inventory applies only to the fixture. Before using a real capture, set the
source policies, webhook approval, and decoy host and route for that observation
point. Unknown sources produce no findings. On a proxy, identify the originating
client from trusted proxy telemetry. A server-side capture may otherwise
attribute all requests to the proxy.

Report the capture flow, destination host, method, rule, and policy that
matched. Keep webhook tokens, query strings, and request bodies out of the
finding. A POST establishes an attempted transfer. Its contents and whether
the receiver accepted it require additional evidence. On encrypted-only
traffic, SNI alone cannot establish a POST or a decoy path.

## Follow-up hunt for similar frameworks

Google reported observing both CAIRN and PentAGI in real investigations in
November 2026. To hunt for automated discovery across tools, start with an
unapproved source touching a private decoy and investigate nearby requests to
distinct routes on the same application. Compare against vulnerability scanner
schedules, synthetic monitors and ordinary deployment traffic. For a cleartext capture or the plaintext side of an intercepting proxy,
go-pcap's `HTTPRequestsFromReaderAt` provides the flow, request direction,
zero-based packet index, and nanosecond capture timestamp. HTTP/2 also supplies
the request stream ID. Inspect frame `PacketIndex + 1` for the decoy hit, then
compare the other requests from that client to the same application within
your investigation window. Several requests in one packet can have the same
timestamp. A zero or backward capture timestamp needs independent timing
evidence.

For a TLS-only capture, use proxy or application
access logs for the per-request timeline. The cleartext scan cannot attribute
decrypted TLS plaintext to its original packet.
[Google threat tracker, November 16, 2026](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold).
