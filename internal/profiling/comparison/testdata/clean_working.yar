// Test features that work in go-yara

rule BasicTextPattern {
    strings:
        $text1 = "hello"
    condition:
        $text1
}

rule HexPattern {
    strings:
        $hex1 = { 68 65 6C 6C 6F }  // "hello"
    condition:
        $hex1
}

rule WidePattern {
    strings:
        $wide1 = "test" wide
    condition:
        $wide1
}

rule NocasePattern {
    strings:
        $nocase1 = "CASE INSENSITIVE" nocase
    condition:
        $nocase1
}

rule MultipleStrings {
    strings:
        $multi_a = "hello"
        $multi_b = "world"
    condition:
        $multi_a and $multi_b
}

rule OrCondition {
    strings:
        $or_a = "hello"
        $or_b = "world"
    condition:
        $or_a or $or_b
}

rule RegexBasic {
    strings:
        $regex1 = /h.llo/
    condition:
        $regex1
}