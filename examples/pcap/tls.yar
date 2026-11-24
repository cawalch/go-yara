import "pcap"

rule tls_name_mismatch {
    condition:
        for any row in pcap.tls : (
            defined row.server_name_match and not row.server_name_match
        )
}

rule tls_name_evidence_missing {
    condition:
        for any row in pcap.tls : (not defined row.server_name_match)
}
