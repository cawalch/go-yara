rule SimpleText {
    meta:
        description = "Simple text matching rule"
        author = "test"
    strings:
        $text1 = "hello world"
        $text2 = "test pattern"
    condition:
        $text1 or $text2
}

rule HexPattern {
    meta:
        description = "Hex pattern matching rule"
        author = "test"
    strings:
        $hex1 = { 48 65 6C 6C 6F } // "Hello" in hex
        $hex2 = { 57 6F 72 6C 64 } // "World" in hex
    condition:
        $hex1 or $hex2
}

rule WideString {
    meta:
        description = "Wide string matching rule"
        author = "test"
    strings:
        $wide1 = "wide string" wide
        $wide2 = "test" wide
    condition:
        $wide1 and $wide2
}

rule CaseInsensitive {
    meta:
        description = "Case insensitive matching"
        author = "test"
    strings:
        $nocase1 = "CASE INSENSITIVE" nocase
        $nocase2 = "Mixed Case" nocase
    condition:
        $nocase1 or $nocase2
}

rule RegexPattern {
    meta:
        description = "Regular expression pattern"
        author = "test"
    strings:
        $regex1 = /test\d+/
        $regex2 = /hello.*world/i
    condition:
        $regex1 or $regex2
}