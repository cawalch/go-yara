rule DemoRule {
    meta:
        author = "go-yara"
        description = "Demonstrates advanced YARA features"
        version = "1.0"
        
    strings:
        $text1 = "malware" nocase wide
        $text2 = "virus" ascii fullword  
        $hex1 = { E2 34 A1 C8 } private
        $regex1 = /[a-z]{32}/i ascii
        
    condition:
        // String matching
        any of them and
        
        // File size operations
        filesize > 1MB and
        filesize < 100KB and
        
        // Data type functions with bitwise operations
        uint32(0) == 0x5A4D and
        uint32(entrypoint) & 0xFF00 == 0x4D00 and
        int16be(entrypoint + 4) > 0 and
        (uint16(2) & 0xFF00) == 0x4D00 and
        uint8(filesize - 1) != 0x00 and
        
        // Shift operations
        (filesize >> 10) < 1024 and
        (uint32(entrypoint) << 2) > 0x1000 and
        
        // Bitwise NOT and XOR
        ~uint16(2) == 0xFFFF and
        (flags ^ 0xAA) == 0x55 and
        
        // Complex combined expressions
        ((uint32(entrypoint) & 0xFF00) >> 8) | 0x01 != 0
}
