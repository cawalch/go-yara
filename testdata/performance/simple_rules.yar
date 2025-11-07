rule pe_detection {
    meta:
        description = "Simple PE file detection"
        author = "performance_test"

    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 }

    condition:
        $mz at 0 and $pe at 128
}

rule elf_detection {
    meta:
        description = "Simple ELF file detection"
        author = "performance_test"

    strings:
        $elf = { 7F 45 4C 46 }

    condition:
        $elf at 0
}

rule malware_strings {
    meta:
        description = "Common malware strings"
        author = "performance_test"

    strings:
        $malware = "malware"
        $virus = "virus"
        $trojan = "trojan"

    condition:
        any of them
}

rule web_detection {
    meta:
        description = "Web-related patterns"
        author = "performance_test"

    strings:
        $http = "HTTP/"
        $html = "<html"
        $eval = "eval("

    condition:
        any of them and filesize < 1000000
}