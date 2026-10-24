// Package wazuh writes normalized events as newline-delimited JSON to a file
// that Wazuh's own log collector (localfile) tails directly. This avoids the
// size limits and framing problems of syslog for structured JSON payloads,
// and lets Wazuh's agent handle buffering/retry if the manager is briefly
// unreachable.
package wazuh

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Writer struct {
	path        string
	maxBytes    int64
	maxBackups  int
	mu          sync.Mutex
	file        *os.File
	currentSize int64
}

func NewWriter(path string, maxFileMB, maxBackups int) (*Writer, error) {
	if maxFileMB <= 0 {
		return nil, fmt.Errorf("maximum Wazuh file size must be greater than zero")
	}
	if maxBackups < 0 {
		return nil, fmt.Errorf("maximum Wazuh backups cannot be negative")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}
	w := &Writer{
		path:       path,
		maxBytes:   int64(maxFileMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("opening wazuh output file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.currentSize = info.Size()
	return nil
}

// WriteEvent appends one JSON object + newline. One JSON object per line is
// required for Wazuh's JSON log parsing to work line-by-line.
func (w *Writer) WriteEvent(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshaling event for wazuh output: %w", err)
	}
	b = append(b, '\n')

	if w.currentSize+int64(len(b)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	n, err := w.file.Write(b)
	if err != nil {
		return fmt.Errorf("writing event to wazuh output file: %w", err)
	}
	w.currentSize += int64(n)
	return nil
}

func (w *Writer) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	if w.maxBackups == 0 {
		if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
			_ = w.open()
			return fmt.Errorf("truncating Wazuh output file: %w", err)
		}
		return w.open()
	}
	oldest := fmt.Sprintf("%s.%d", w.path, w.maxBackups)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		_ = w.open()
		return fmt.Errorf("removing oldest Wazuh backup: %w", err)
	}
	// Shift existing backups from oldest to newest, checking each filesystem error.
	for i := w.maxBackups; i >= 2; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i-1)
		dst := fmt.Sprintf("%s.%d", w.path, i)
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			_ = w.open()
			return fmt.Errorf("shifting Wazuh backup %s: %w", src, err)
		}
	}
	if err := os.Rename(w.path, fmt.Sprintf("%s.1", w.path)); err != nil && !os.IsNotExist(err) {
		_ = w.open()
		return fmt.Errorf("rotating Wazuh output file: %w", err)
	}
	return w.open()
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}
