package wazuh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotateWithNoBackupsTruncatesCurrentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	w, err := NewWriter(path, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.maxBytes = 1
	if err := w.WriteEvent("one"); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteEvent("two"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len("\"two\"\n")) {
		t.Fatalf("current file size = %d, want only the last event", info.Size())
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("unexpected backup file, stat error = %v", err)
	}
}
