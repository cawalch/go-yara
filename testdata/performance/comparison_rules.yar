rule simple_string {
    strings:
        $test = "test"
        $malware = "malware"
        $virus = "virus"
        $trojan = "trojan"
    condition:
        any of them
}