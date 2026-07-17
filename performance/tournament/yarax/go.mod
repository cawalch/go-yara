module github.com/cawalch/go-yara/performance/tournament/yarax

go 1.26.0

require (
	github.com/VirusTotal/yara-x/go v1.19.0
	github.com/cawalch/go-yara v0.0.0
)

require google.golang.org/protobuf v1.33.0 // indirect

replace github.com/cawalch/go-yara => ../../..
