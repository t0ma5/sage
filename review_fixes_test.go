package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestLooksLikePathNeedsAFullPath(t *testing.T) {
	for _, p := range []string{`D:\k.txt`, `D:/k.txt`, `\\nas\keys\k.txt`, `"C:\My keys\k.txt"`} {
		if !looksLikePath(p) {
			t.Errorf("%q should count as a path", p)
		}
	}
	// A passphrase with a colon or slash, pasted into the wrong field, is not saved.
	for _, p := range []string{"correct:horse/battery", "a/b", "x:y", "hunter2", `1:\x`} {
		if looksLikePath(p) {
			t.Errorf("%q should not count as a path", p)
		}
	}
	if got := keepLines("C:\\keys\\me.txt\ncorrect:horse/battery", looksLikePath); got != `C:\keys\me.txt` {
		t.Errorf("keepLines kept %q", got)
	}
}

func TestPartLeftErrorKeepsTheCause(t *testing.T) {
	cause := errors.New("boom")
	err := error(&partLeftError{err: cause, Part: `C:\x.age.part`})
	var left *partLeftError
	if !errors.Is(err, cause) || !errors.As(err, &left) || left.Part != `C:\x.age.part` || err.Error() != "boom" {
		t.Fatalf("unexpected: %v %+v", err, left)
	}
}

// A cancelled file whose partial output can't be deleted (a scanner holds it) is
// named in the summary instead of being left behind silently.
func TestUndeletablePartIsReported(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(src, []byte(strings.Repeat("x", 8<<20)), 0o600); err != nil {
		t.Fatal(err)
	}
	id, _ := age.GenerateX25519Identity()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var release func()
	s := &SageService{}
	s.onBytes = func() {
		if release == nil {
			release = holdWithoutDeleteSharing(t, src+".age.part")
			cancel()
		}
	}
	done := s.run(ctx, []string{src}, true, []age.Recipient{id.Recipient()}, nil, false)
	if release != nil {
		release()
	}
	if release == nil {
		t.Skip("could not hold the partial file open on this OS")
	}
	if !strings.Contains(done.Summary, "couldn't be deleted") || !strings.Contains(done.Summary, "a.txt.age.part") {
		t.Fatalf("summary doesn't name the leftover: %q", done.Summary)
	}
	if len(done.Results) != 1 || !strings.Contains(done.Results[0].Error, "couldn't be deleted") {
		t.Fatalf("the row doesn't say so: %+v", done.Results)
	}
}
