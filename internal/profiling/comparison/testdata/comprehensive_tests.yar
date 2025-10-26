// Comprehensive test suite to identify missing features and bugs in go-yara

rule BasicTextString {
    strings:
        $text1 = "hello"
        $text2 = "world"
    condition:
        $text1 or $text2
}

rule WideStringPattern {
    strings:
        $wide = "test" wide
    condition:
        $wide
}

rule NocasePattern {
    strings:
        $nocase = "CASE INSENSITIVE" nocase
    condition:
        $nocase
}

rule HexPattern {
    strings:
        $hex = { 48 65 6C 6C 6F }  // "Hello"
    condition:
        $hex
}

rule RegexPattern {
    strings:
        $regex = /h.llo/  // h?llo
    condition:
        $regex
}

rule MultipleModifiers {
    strings:
        $wide_nocase = "test" wide nocase
    condition:
        $wide_nocase
}

rule HexWithWildcards {
    strings:
        $hex_wild = { 48 65 ?? 6C 6F }  // H?llo with wildcard
    condition:
        $hex_wild
}

rule StringCount {
    strings:
        $s1 = "hello"
        $s2 = "world"
    condition:
        #s1 > 0 and #s2 > 0
}

rule StringAtOffset {
    strings:
        $pattern = "test"
    condition:
        $pattern at 0
}

rule StringInRange {
    strings:
        $pattern = "test"
    condition:
        $pattern in (0..100)
}

rule Alternatives {
    strings:
        $pattern = /hello|world/
    condition:
        $pattern
}

rule CharacterClass {
    strings:
        $pattern = /[a-z]+/
    condition:
        $pattern
}

rule Repetition {
    strings:
        $pattern = /a+/
    condition:
        $pattern
}

rule ComplexRegex {
    strings:
        $pattern = /https?:\/\/[a-zA-Z0-9\.]+\/[a-zA-Z0-9]+/
    condition:
        $pattern
}

rule MultipleConditions {
    strings:
        $a = "alpha"
        $b = "beta"
        $c = "gamma"
    condition:
        ($a and $b) or $c
}

rule NestedLogic {
    strings:
        $a = "test"
        $b = "hello"
        $c = "world"
    condition:
        ($a and $b) or ($a and $c)
}

rule HexJump {
    strings:
        $pattern = { 4D 5A [4] 50 45 }  // MZ??PE with 4-byte jump
    condition:
        $pattern
}

rule HexAlternatives {
    strings:
        $pattern = { (01 | 02 | 03) 04 }
    condition:
        $pattern
}