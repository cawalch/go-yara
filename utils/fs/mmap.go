package fs

// MinMmapFileSize is the minimum file size (128 KB) at which memory mapping
// is preferred over heap allocation.
const MinMmapFileSize = 128 * 1024

// MapFile maps the named file into memory read-only.
//
// On Unix/POSIX platforms (darwin, linux, freebsd, etc.), MapFile uses
// syscall.Mmap to create a zero-copy memory mapping backed by the operating system page cache.
// On Windows or fallback platforms, or for empty files, it gracefully falls back
// to standard file reading.
//
// The returned cleanup function must be called when the caller is done using
// data to release system resources (e.g. via syscall.Munmap). cleanup is safe
// to call multiple times and safe when data is empty or nil.
func MapFile(filename string) ([]byte, func(), error) {
	return mapFileOS(filename)
}
