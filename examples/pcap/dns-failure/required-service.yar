external dns_rcode

rule required_service_dns_failure {
    strings:
        $service = "api.example" nocase
    condition:
        $service at 0 and !service[1] == filesize and
        (dns_rcode == 2 or dns_rcode == 3)
}
