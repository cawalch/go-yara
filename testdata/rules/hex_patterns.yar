rule HexPattern {
    meta:
        description = "Hex pattern matching test"
        author = "profiler"
    strings:
        $a = { 4D 41 4C 57 41 52 45 } // "MALWARE"
        $b = { 53 55 53 50 49 43 49 4F 55 53 } // "SUSPICIOUS"
        $c = { 50 41 54 54 45 52 4E } // "PATTERN"
    condition:
        $a or $b or $c
}

rule ComplexHex {
    meta:
        description = "Complex hex pattern with jumps"
        author = "profiler"
    strings:
        $a = { 4D 41 4C [2-4] 57 41 52 45 }
        $b = { 53 55 53 [1-3] 49 43 49 4F 55 53 }
        $c = { 50 41 54 54 [0-5] 45 52 4E }
    condition:
        $a or $b or $c
}