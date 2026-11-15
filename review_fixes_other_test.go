//go:build !windows

package main

import "testing"

// Only Windows refuses to delete a file another program holds open.
func holdWithoutDeleteSharing(*testing.T, string) func() { return nil }
