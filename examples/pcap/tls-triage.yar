import "pcap"

// Count flows with positive mismatch evidence; missing evidence does not count.
rule tls_multiple_name_mismatches {
    condition:
        for 2 row in pcap.tls : (
            defined row.server_name_match and not row.server_name_match
        )
}

// Useful after a proxy/certificate rollout: both outcomes occur in this capture.
// This does not establish that the flows used the same listener or hostname.
rule tls_mixed_name_results {
    condition:
        for any row in pcap.tls : (row.server_name_match) and
        for any row in pcap.tls : (
            defined row.server_name_match and not row.server_name_match
        )
}

// Preserve an observed mismatch while flagging incomplete comparison coverage.
rule tls_mismatch_with_evidence_gaps {
    condition:
        for any row in pcap.tls : (
            defined row.server_name_match and not row.server_name_match
        ) and
        for any row in pcap.tls : (not defined row.server_name_match)
}

// Require at least one row: "all" alone also succeeds for an empty collection.
// This asserts name agreement only, not certificate trust or capture completeness.
rule tls_all_observed_names_match {
    condition:
        defined pcap.tls[0].flow_index and
        for all row in pcap.tls : (
            defined row.server_name_match and row.server_name_match
        )
}
