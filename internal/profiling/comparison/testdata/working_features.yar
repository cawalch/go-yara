// Test features that work in go-yara

rule BasicTextPattern {
    strings:
        $text = "hello"
    condition:
        $text
}

rule HexPattern {
    strings:
        $hex = { 68 65 6C 6C 6F }  // "hello"
    condition:
        $hex
}

rule WidePattern {
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

rule MultipleStrings {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        $a and $b
}

rule OrCondition {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        $a or $b
}

rule RegexBasic {
    strings:
        $regex = /h.llo/
    condition:
        $regex
}