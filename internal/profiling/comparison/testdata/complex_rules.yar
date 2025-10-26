rule ComplexPatternMatching {
    meta:
        description = "Complex pattern matching with multiple conditions"
        author = "test"
        date = "2024-01-01"
    strings:
        $malware = "malware"
        $pe_header = { 4D 5A 90 00 03 00 00 00 } // PE header
        $url_pattern = /https?:\/\/[a-zA-Z0-9\.]+\/[a-zA-Z0-9]+/
        $suspicious = "suspicious" wide
        $exploit_hex = { 45 78 70 6C 6F 69 74 } // "Exploit" in hex
    condition:
        ($malware and $pe_header) or ($url_pattern and $suspicious) or $exploit_hex
}

rule MultiStringRule {
    meta:
        description = "Rule with many string patterns"
        author = "test"
    strings:
        $str1 = "string1"
        $str2 = "string2"
        $str3 = "string3"
        $str4 = "string4"
        $str5 = "string5"
        $str6 = "string6"
        $str7 = "string7"
        $str8 = "string8"
        $str9 = "string9"
        $str10 = "string10"
        $hex1 = { 01 02 03 04 }
        $hex2 = { AA BB CC DD }
        $regex1 = /test\d+/i
        $regex2 = /pattern[abc]/
    condition:
        any of them
}

rule PerformanceTest {
    meta:
        description = "Performance testing rule with complex logic"
        author = "test"
    strings:
        $trigger1 = "trigger"
        $trigger2 = "activate"
        $payload = { DE AD BE EF }
        $wide_payload = "payload" wide
        $regex_payload = /payload[0-9a-f]+/
    condition:
        ($trigger1 or $trigger2) and ($payload or $wide_payload or $regex_payload)
}

rule NestedConditions {
    meta:
        description = "Rule with nested logical conditions"
        author = "test"
    strings:
        $cond1 = "condition1"
        $cond2 = "condition2"
        $cond3 = "condition3"
        $cond4 = "condition4"
    condition:
        ($cond1 and $cond2) or ($cond3 and $cond4) or
        ($cond1 and $cond3) or ($cond2 and $cond4)
}

rule StringCountRule {
    meta:
        description = "Rule that checks string count"
        author = "test"
    strings:
        $alpha = "alpha"
        $beta = "beta"
        $gamma = "gamma"
        $delta = "delta"
    condition:
        $alpha and $beta
}