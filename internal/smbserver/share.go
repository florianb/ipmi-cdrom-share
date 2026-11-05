package smbserver

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Share is the single read-only file offered to clients. ReadAt is safe for
// concurrent use, so one Share serves all connections.
type Share struct {
	file    *os.File
	name    string
	size    int64
	modTime time.Time
}

// OpenShare opens the file at path for serving.
func OpenShare(path string) (*Share, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open share: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat share: %w", err)
	}
	if info.IsDir() {
		f.Close()
		return nil, fmt.Errorf("%s is a directory, not a file", path)
	}
	return &Share{
		file:    f,
		name:    filepath.Base(path),
		size:    info.Size(),
		modTime: info.ModTime(),
	}, nil
}

// Name returns the file name clients see.
func (s *Share) Name() string { return s.name }

// Size returns the file size in bytes.
func (s *Share) Size() int64 { return s.size }

// ReadAt implements io.ReaderAt.
func (s *Share) ReadAt(p []byte, off int64) (int, error) { return s.file.ReadAt(p, off) }

// Close releases the underlying file.
func (s *Share) Close() error { return s.file.Close() }
