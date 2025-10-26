rule TestInOperator {
    strings:
        $test = "hello"
    condition:
        $test in (0..10)  // Should match - "hello" is at offset 0, within range 0-10
}