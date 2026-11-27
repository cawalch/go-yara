package compiler

import (
	"context"
	"errors"

	pcap "github.com/cawalch/go-pcap"
)

// HTTP1ResponseScan carries the artifact evidence and the file-rule result for
// one response. Result is present after a successful scan. A nil result with
// no error means the artifact was partial or unavailable and was skipped.
type HTTP1ResponseScan struct {
	// Artifact borrows the body and packet slices passed to ScanHTTP1Response.
	// len(Artifact.Body) is the available decoded byte length.
	Artifact pcap.HTTP1ResponseArtifact
	Result   *ScanResult
}

// ScanHTTP1Response runs the scanner's compiled rules on a complete artifact
// from [pcap.HTTP1Transaction.ResponseArtifact], including a complete empty
// entity. It applies the same scanner options and cancellation as
// [Scanner.ScanWithContext]. File offsets and filesize refer to the decoded
// entity. Artifact packet references retain their original capture coordinates.
// Capture-level extraction limits apply when obtaining the artifact from
// go-pcap. This method also checks the per-entity byte limit.
func (s *Scanner) ScanHTTP1Response(ctx context.Context, artifact pcap.HTTP1ResponseArtifact) (HTTP1ResponseScan, error) {
	scan := HTTP1ResponseScan{Artifact: artifact}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return scan, err
		}
	}
	if artifact.Coverage != pcap.HTTP1ArtifactComplete {
		return scan, nil
	}
	if len(artifact.Body) > pcap.MaxHTTPBodyBytes {
		return scan, pcap.ErrHTTPLimit
	}
	if s == nil || s.program == nil {
		return scan, errors.New("HTTP response scan requires a compiled program")
	}
	result, err := s.ScanWithContext(ctx, artifact.Body)
	if err == nil {
		scan.Result = result
	}
	return scan, err
}
