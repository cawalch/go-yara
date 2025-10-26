rule SimpleStrings {
    meta:
        description = "Simple string matching test"
        author = "profiler"
    strings:
        $a = "MALWARE"
        $b = "SUSPICIOUS"
        $c = "PATTERN"
    condition:
        $a or $b or $c
}

rule MultipleStrings {
    meta:
        description = "Multiple string patterns"
        author = "profiler"
    strings:
        $s1 = "test"
        $s2 = "pattern"
        $s3 = "match"
        $s4 = "search"
        $s5 = "find"
    condition:
        any of them
}