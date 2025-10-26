rule RegexSimple {
    meta:
        description = "Simple regex patterns"
        author = "profiler"
    strings:
        $a = /MALWARE/
        $b = /SUSPICIOUS/
        $c = /PATTERN/
    condition:
        $a or $b or $c
}

rule RegexComplex {
    meta:
        description = "Complex regex patterns"
        author = "profiler"
    strings:
        $a = /M[AL]*WARE/
        $b = /SUS.*IOUS/
        $c = /PATT.*RN/
        $d = /\d{4}-\d{2}-\d{2}/ // Date pattern
        $e = /[A-Z]{3,10}/      // Uppercase word
    condition:
        any of them
}