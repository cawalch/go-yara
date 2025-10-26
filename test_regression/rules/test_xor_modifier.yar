rule TestXorModifier {
    strings:
        $xor = "test" xor 0x42
    condition:
        $xor
}