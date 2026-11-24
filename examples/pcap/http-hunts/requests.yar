external destination_host
external http_method
external restricted_server
external approved_webhook
external decoy_route
external approved_scanner

rule unexpected_server_webhook_post {
    condition:
        defined restricted_server and restricted_server and
        defined approved_webhook and not approved_webhook and
        destination_host iequals "webhook.site" and http_method == "POST"
}

rule unapproved_decoy_route_access {
    condition:
        defined decoy_route and decoy_route and
        defined approved_scanner and not approved_scanner
}
