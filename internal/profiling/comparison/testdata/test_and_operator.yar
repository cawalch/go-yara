rule TestAndOperator {
    strings:
        $a = "hello"
        $b = "world"
    condition:
        $a and $b
}