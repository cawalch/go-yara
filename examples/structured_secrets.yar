// Synthetic examples of go-yara's opt-in capture/evidence extension.
// These are extraction examples, not a maintained detector corpus.

rule gcp_service_account_candidate : secret_example {
    strings:
        $kind = /"type"[ ]*:[ ]*"service_account"/
        $endpoint = /"token_uri"[ ]*:[ ]*"([^"]+)"/ capture(endpoint = 1)
        $identity = /"client_email"[ ]*:[ ]*"([^"]+)"/ capture(username = 1)
        $key = /"private_key"[ ]*:[ ]*"([^"]+)"/ capture(secret = 1)
    evidence:
        credential = (endpoint, username, secret) within 8KB of secret
    condition:
        $kind and $key
}

rule tls_private_key_candidate : secret_example {
    strings:
        $pem = /(-----BEGIN [A-Z ]*PRIVATE KEY-----\r?\n.+\r?\n-----END [A-Z ]*PRIVATE KEY-----)/s capture(secret = 1)
    evidence:
        private_key = (secret) within 0 of secret
    condition:
        $pem
}

rule aws_assignment_candidate : secret_example {
    strings:
        $access = /aws_access_key_id[ ]*[:=][ ]*["']?([A-Z0-9]{20})/i capture(access_key = 1)
        $secret = /aws_secret_access_key[ ]*[:=][ ]*["']?([A-Za-z0-9\/+=]{40})/i capture(secret = 1)
        $endpoint = /endpoint[ ]*[:=][ ]*["']?([^"' \n]+)/i capture(endpoint = 1)
    evidence:
        credential = (endpoint, access_key, secret) within 4KB of secret
    condition:
        $access or $secret
}

rule database_uri_candidate : secret_example {
    strings:
        $uri = /(postgres|mysql):\/\/([^: ]+):([^@ ]+)@([^\/ ]+)/
            capture(username = 2, secret = 3, endpoint = 4)
    evidence:
        credential = (endpoint, username, secret) within 0 of secret
    condition:
        $uri
}

rule freeform_token_candidate : secret_example {
    strings:
        $message = /(api[_ -]?key|token)[ ]*(is|=|:)[ ]*([A-Za-z0-9_-]{16,})/i capture(secret = 3)
    evidence:
        token = (secret) within 0 of secret
    condition:
        $message
}
