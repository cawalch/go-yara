rule SimpleTest {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        $a or $b
}

