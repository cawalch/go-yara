// Test specific missing features in go-yara

rule TestAtOperator {
    strings:
        $pattern = "test"
    condition:
        $pattern at 0
}

rule TestInOperator {
    strings:
        $pattern = "test"
    condition:
        $pattern in (0..100)
}

rule TestStringCount {
    strings:
        $s1 = "test"
    condition:
        #s1 > 0
}

rule TestMultipleStringReferences {
    strings:
        $s1 = "hello"
        $s2 = "world"
    condition:
        $s1 and $s2
}

rule TestAlternatives {
    strings:
        $pattern = /hello|world/
    condition:
        $pattern
}