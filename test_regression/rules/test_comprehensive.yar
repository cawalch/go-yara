rule TestComprehensiveFeatures {
    strings:
        $basic = "hello"
        $wide = "world" wide
        $nocase = "TEST" nocase
        $xor = "secret" xor 0xAA
        $regex = /https?:\/\/[a-zA-Z0-9\.]+\//
    condition:
        ($basic at 0) and ($wide in (10..20)) and $nocase and $xor and $regex
}