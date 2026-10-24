cat > greeting.yar <<'YARA'
rule greeting {
    strings:
        $text = "hello" nocase
    condition:
        $text
}
YARA
printf 'Hello from Go\n' > sample.txt
go-yara greeting.yar sample.txt
go-yara greeting.yar --json -s sample.txt
