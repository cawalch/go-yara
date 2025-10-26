rule SimpleTest {
    strings:
        $test = "hello"
    condition:
        $test
}