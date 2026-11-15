package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

// holdWithoutDeleteSharing opens path the way some scanners do (no FILE_SHARE_DELETE),
// so deleting it fails until the returned func closes it.
func holdWithoutDeleteSharing(t *testing.T, path string) func() {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return func() { windows.CloseHandle(h) }
}
