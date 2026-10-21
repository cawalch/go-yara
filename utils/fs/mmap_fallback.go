//go:build !unix

package fs

import (
	"fmt"
	"os"
)

func mapFileOS(filename string) ([]byte, func(), error) {
	info, err := os.Stat(filename)
	if err != nil {
		return nil, nil, err
	}
	if info.IsDir() {
		return nil, nil, fmt.Errorf("cannot mmap directory: %s", filename)
	}
	if info.Size() == 0 {
		return []byte{}, func() {}, nil
	}

	data, err := os.ReadFile(filename) // #nosec G304 - intentional fallback read
	if err != nil {
		return nil, nil, fmt.Errorf("reading file for mmap fallback: %w", err)
	}
	return data, func() {}, nil
}
