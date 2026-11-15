//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// renameNoReplace moves a file without ever replacing an existing one.
// os.Rename on Windows passes MOVEFILE_REPLACE_EXISTING, so it is not used here.
// Without that flag MoveFileEx fails with ERROR_ALREADY_EXISTS, which works on
// every filesystem, including virtual drives that have no hard links.
func renameNoReplace(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(longPath(from))
	if err != nil {
		return err
	}
	toPtr, err := windows.UTF16PtrFromString(longPath(to))
	if err != nil {
		return err
	}
	err = retryWhileLocked(func() error {
		return windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_WRITE_THROUGH)
	})
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}

// retryWhileLocked retries briefly while Windows reports the file as in use:
// antivirus and the search indexer often open a new file for a moment.
func retryWhileLocked(action func() error) error {
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		err = action()
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// longPath adds the \\?\ prefix that lets Win32 calls use paths longer than 260
// characters. Go's os package does this internally; direct Win32 calls don't.
func longPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) || !filepath.IsAbs(p) {
		return p
	}
	p = filepath.Clean(p) // \\?\ paths are taken literally: no "." or "/"
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + p[2:] // \\server\share\... -> \\?\UNC\server\share\...
	}
	return `\\?\` + p
}

// isElevated reports whether sage runs as administrator *with a normal session
// alongside* (a UAC split token, TokenElevationTypeFull). Only then are drives
// mapped by the normal session hidden from sage and drag and drop from Explorer
// blocked. With UAC off, or the built-in Administrator account, there is no
// normal session to switch to, so there is nothing to warn about.
func isElevated() bool {
	var elevationType, size uint32
	err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenElevationType,
		(*byte)(unsafe.Pointer(&elevationType)), uint32(unsafe.Sizeof(elevationType)), &size)
	return err == nil && elevationType == 2 // TokenElevationTypeFull
}

// showInExplorer opens the file's folder in Explorer with the file selected.
func showInExplorer(path string) error {
	// Explorer accepts "/select," followed by the path as the next argument; Go quotes a
	// path with spaces. Explorer's exit code is meaningless, so Start, not Run.
	return exec.Command("explorer.exe", "/select,", path).Start()
}

// isNetUnreachable reports whether err means a network share can't be reached:
// bad network path (53), network name deleted (64), bad network name (67), no network (1222).
func isNetUnreachable(err error) bool {
	for _, code := range []windows.Errno{53, 64, 67, 1222} {
		if errors.Is(err, code) {
			return true
		}
	}
	return false
}
