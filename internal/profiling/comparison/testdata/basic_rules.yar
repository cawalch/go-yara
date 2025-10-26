rule HelloWorld {
    meta:
        description = "Basic hello world rule"
        author = "test"
    strings:
        $hello = "hello world"
    condition:
        $hello
}

rule TestPattern {
    meta:
        description = "Test pattern rule"
        author = "test"
    strings:
        $test = "test pattern"
    condition:
        $test
}

rule WidePattern {
    meta:
        description = "Wide pattern rule"
        author = "test"
    strings:
        $wide = "wide" wide
    condition:
        $wide
}

rule HexPattern {
    meta:
        description = "Hex pattern rule"
        author = "test"
    strings:
        $hex = { 48 65 6C 6C 6F }
    condition:
        $hex
}

rule CaseInsensitive {
    meta:
        description = "Case insensitive rule"
        author = "test"
    strings:
        $nocase = "CASE INSENSITIVE" nocase
    condition:
        $nocase
}