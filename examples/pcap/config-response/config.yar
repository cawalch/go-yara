import "pcap"

rule tampered_config_response {
  condition:
    for any tx in pcap.http : (
      tx.method == "GET" and tx.target == "/config.json" and
      tx.pairing == "confirmed" and tx.response_body_state == "complete" and
      tx.response_body contains "demo-tampered"
    )
}
