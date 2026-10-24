set -eu
cat > catalog.yar <<'YARA'
rule document : inventory {
    meta:
        category = "example"
    strings:
        $text = "hello" nocase
    condition:
        $text
}
YARA
mkdir -p cli-samples/nested
printf 'hello\n' > cli-samples/one.txt
printf 'HELLO\n' > cli-samples/nested/two.txt
go-yara catalog.yar -r -p 2 --json -g -m cli-samples
