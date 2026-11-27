import "pcap"

rule revoked_update {
  condition:
    for any tx in pcap.http : (
      tx.target == "/diagnostics" and tx.response_body contains "diagnostics-only"
    )
}
