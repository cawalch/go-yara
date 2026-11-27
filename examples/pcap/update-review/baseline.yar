import "pcap"

rule revoked_update {
  condition:
    for any tx in pcap.http : (
      tx.authority == "updates.example" and tx.target == "/updates/client"
    ) and
    for any tx in pcap.http : (
      tx.response_body contains "artifact_id=REVOKED-BUILD-042"
    )
}

rule observed_update_dns {
  condition:
    for any lookup in pcap.dns : (
      lookup.pairing == "paired" and
      lookup.query.questions[0].name == "updates.example" and
      lookup.reply.complete and lookup.reply.rcode == 0 and
      lookup.reply.answers[0].address == "192.0.2.20"
    )
}
