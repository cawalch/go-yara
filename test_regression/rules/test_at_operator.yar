rule TestAtOperator {
    strings:
        $test = "hello"
    condition:
        $test at 0
}