package compiler

import (
	"context"
	"errors"

	pcap "github.com/cawalch/go-pcap"
)

// ScanWithPCAPHTTP1 scans the original capture bytes with a caller-supplied
// view of pcap.http. Rows must come from that capture and are borrowed for the
// duration of the scan. An empty view supplies a defined, empty array.
// Other fields of the built-in pcap module still inspect the original capture.
// Use this operation to check how changing the HTTP view affects a rule.
func (s *Scanner) ScanWithPCAPHTTP1(ctx context.Context, data []byte, rows []pcap.HTTP1Transaction) (*ScanResult, error) {
	if s == nil {
		return nil, errors.New("PCAP HTTP view requires a scanner")
	}
	if _, bound := s.moduleData["pcap"]; bound {
		return nil, errors.New("PCAP HTTP view requires the built-in PCAP module")
	}
	s.moduleCache.pcapHTTPRows = &rows
	defer func() {
		s.moduleCache.pcapHTTPRows = nil
		s.moduleCache.pcap = nil
	}()
	return s.ScanWithContext(ctx, data)
}
