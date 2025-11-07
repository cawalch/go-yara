rule pe_malware_detection {
    meta:
        description = "Detects PE files with suspicious characteristics"
        author = "performance_test"
        malware_type = "generic"

    strings:
        $mz_header = { 4D 5A }
        $pe_header = { 50 45 00 00 }
        $suspicious_import = "CreateRemoteThread"
        $malware_string = "malware"
        $packed_section = /UPX[0-9]\./

    condition:
        $mz_header at 0 and
        $pe_header at 60 and
        ($suspicious_import or $malware_string or $packed_section)
}

rule elf_backdoor {
    meta:
        description = "Detects ELF files with backdoor characteristics"
        author = "performance_test"
        malware_type = "backdoor"

    strings:
        $elf_header = { 7F 45 4C 46 }
        $backdoor_pattern = "backdoor"
        $network_comm = /socket|connect|bind/
        $suspicious_domain = /[a-z0-9]{20,}\.(tk|ml|ga)/

    condition:
        $elf_header at 0 and
        ($backdoor_pattern or any of ($network_comm, $suspicious_domain))
}

rule webshell_detection {
    meta:
        description = "Detects webshells in PHP/ASP files"
        author = "performance_test"
        malware_type = "webshell"

    strings:
        $php_eval = "eval("
        $php_system = "system("
        $asp_wscript = "WScript.Shell"
        $shell_pattern = /shell_\w+|cmd_\w+/
        $base64_decode = "base64_decode("

    condition:
        any of them and filesize < 1000000
}

rule ransomware_indicators {
    meta:
        description = "Detects ransomware-like behavior patterns"
        author = "performance_test"
        malware_type = "ransomware"

    strings:
        $encryption_api = /CryptEncrypt|CryptCreateHash/
        $file_extension = /\.(locked|encrypted|crypted)/
        $ransom_note = "Your files are encrypted"
        $bitcoin_wallet = /[1-9A-HJ-NP-Za-km-z]{26,35}/
        $tor_access = ".onion"

    condition:
        3 of them
}

rule banker_trojan {
    meta:
        description = "Detects banking trojan characteristics"
        author = "performance_test"
        malware_type = "banker"

    strings:
        $banking_domain = /(paypal|chase|bankofamerica|wellsfargo)/i
        $keylogger_api = "GetAsyncKeyState"
        $form_grabbing = /form|input|password/i
        $browser_hook = "InternetExplorer.Application"
        $financial_data = /credit.card|ssn|social.security/i

    condition:
        any of ($banking_domain, $financial_data) and
        any of ($keylogger_api, $form_grabbing, $browser_hook)
}

rule ddos_bot {
    meta:
        description = "Detects DDoS bot functionality"
        author = "performance_test"
        malware_type = "ddos"

    strings:
        $ddos_keyword = /ddos|botnet|flood/i
        $http_flood = "POST / HTTP/1.1"
        $syn_flood = /SYN|UDP|ICMP flood/
        $c2_server = /c2\..*|cmd\..*|control\./i
        $amplification = /dns|ntp|memcached amplification/i

    condition:
        any of them
}

rule miner_malware {
    meta:
        description = "Detects cryptocurrency mining malware"
        author = "performance_test"
        malware_type = "miner"

    strings:
        $mining_pool = /pool|stratum|mining/
        $crypto_algo = /SHA-256|Scrypt|Ethash|RandomX/
        $coin_name = /(bitcoin|ethereum|monero|cryptocurrency)/i
        $cpu_usage = "CPU 100%"
        $mining_binary = /(xmrig|cpuminer|ccminer)/

    condition:
        2 of them
}

rule apt_surveillance {
    meta:
        description = "Detects APT surveillance tools"
        author = "performance_test"
        malware_type = "apt"

    strings:
        $surveillance_keyword = /keylog|screenshot|webcam|microphone/i
        $data_exfil = /exfiltrate|steal|leak/i
        $persistence = /autorun|startup|registry|runonce/i
        $c2_communication = /http://.*\/api|https:\/\/.*\/c2/
        $stealth = /rootkit|hidden|invisible/i

    condition:
        $surveillance_keyword and
        any of ($data_exfil, $persistence, $c2_communication, $stealth)
}