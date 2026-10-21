//go:build unix

package fs

import (
	"fmt"
	"math"
	"os"
	"sync"
	"syscall"
)

func mapFileOS(filename string) ([]byte, func(), error) {
	file, err := os.Open(filename) // #nosec G304 - caller intentionally maps this path
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat %s: %w", filename, err)
	}
	if info.IsDir() {
		return nil, nil, fmt.Errorf("cannot mmap directory: %s", filename)
	}

	size := info.Size()
	if size == 0 {
		return []byte{}, func() {}, nil
	}
	if size < 0 || size > int64(math.MaxInt) {
		return nil, nil, fmt.Errorf("invalid file size %d for mmap: %s", size, filename)
	}

	data, err := syscall.Mmap(int(file.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, fmt.Errorf("mmap %s: %w", filename, err)
	}

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			if len(data) > 0 {
				_ = syscall.Munmap(data)
			}
		})
	}

	return data, cleanup, nil
}
