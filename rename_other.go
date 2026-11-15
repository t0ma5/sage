//go:build !windows

package main

import "os"

// renameNoReplace moves a file without ever replacing an existing one. A hard
// link fails if the target exists, and the source is removed only after it
// succeeded. (sage targets Windows; this keeps the core testable elsewhere.)
func renameNoReplace(from, to string) error {
	if err := os.Link(from, to); err != nil {
		return err
	}
	return os.Remove(from)
}

func retryWhileLocked(action func() error) error { return action() }

func isElevated() bool { return false }

func isNetUnreachable(error) bool { return false }

func showInExplorer(string) error { return nil }
