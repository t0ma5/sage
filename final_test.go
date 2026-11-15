package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// Tests for the gaps listed in the final review.

func TestStartRechecksTheRealPassphrase(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "x.txt")
	write(t, plain, "x")
	s := &SageService{}
	// The window's summary claims the passphrases match, but the real ones don't.
	err := s.Start(Request{Files: []string{plain}, Passphrase: "a", Confirm: "b",
		PassInfo: &PassInfo{Set: true, ConfirmSet: true, Match: true}})
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("got %v", err)
	}
}

func TestStartRefusesASecondJob(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "x.txt")
	write(t, plain, "x")
	s := &SageService{running: true}
	err := s.Start(Request{Files: []string{plain}, Passphrase: "p", Confirm: "p"})
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("got %v", err)
	}
}

func TestStartTakesModeFromFiles(t *testing.T) {
	dir := t.TempDir()
	enc := encryptWith(t, dir, "m.txt", "mode", "pw")
	s := &SageService{}
	// The window claims "encrypt"; the file is .age, so Go decrypts (no confirm needed).
	if err := s.Start(Request{Files: []string{enc}, Mode: "encrypt", Passphrase: "pw"}); err != nil {
		t.Fatal(err)
	}
	s.inflight.Wait()
	if read(t, filepath.Join(dir, "m.txt")) != "mode" {
		t.Fatal("file was not decrypted")
	}
	if s.running {
		t.Fatal("job still marked as running")
	}
}

func TestCancelMidFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "big.bin")
	write(t, src, strings.Repeat("z", 8<<20))
	r, _ := scryptPair(t, "p")
	ctx, cancel := context.WithCancel(context.Background())
	s := &SageService{onBytes: cancel} // cancel as soon as data starts flowing
	done := s.run(ctx, []string{src}, true, []age.Recipient{r}, nil, false)
	if !strings.Contains(done.Summary, "not processed (cancelled)") || len(done.Remaining) != 1 {
		t.Fatalf("%+v", done)
	}
	if _, err := os.Stat(src + ".age"); err == nil {
		t.Fatal("cancelled file left an output")
	}
	// The row is told it was cancelled (the window puts it back to "ready"), not that it failed.
	if len(done.Results) != 1 || !done.Results[0].Cancelled || done.Results[0].OK || done.Results[0].Path != src {
		t.Fatalf("results: %+v", done.Results)
	}
	noPartFiles(t, dir)
}

func TestOpenFolderMissingFile(t *testing.T) {
	err := (&SageService{}).OpenFolder(filepath.Join(t.TempDir(), "gone.age"))
	if err == nil || !strings.Contains(err.Error(), "gone.age isn't there any more") {
		t.Fatalf("err: %v", err)
	}
}

func TestOldSettingsWithWriteLog(t *testing.T) {
	// Settings saved by v0.1.0 still have "writeLog"; it is ignored, and dropped on the next save.
	dir := t.TempDir()
	write(t, filepath.Join(dir, settingsFile), `{"activeTab":"recipient","recipients":"age1abc","writeLog":true}`)
	s := &SageService{baseDir: dir}
	st := s.LoadSettings()
	if st.Notice != "" || st.ActiveTab != "recipient" || st.Recipients != "age1abc" {
		t.Fatalf("%+v", st)
	}
	if err := s.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(t, filepath.Join(dir, settingsFile)), "writeLog") {
		t.Fatal("writeLog was saved again")
	}
}

func TestDamagedSettingsWhenBadAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	s := &SageService{baseDir: dir}
	write(t, filepath.Join(dir, settingsFile+".bad"), "older damage")
	write(t, filepath.Join(dir, settingsFile), "{broken")
	st := s.LoadSettings()
	if !strings.Contains(st.Notice, "sageSettings.json (1).bad") && !strings.Contains(st.Notice, ".bad (1)") {
		t.Fatalf("notice %q", st.Notice)
	}
	if read(t, filepath.Join(dir, settingsFile+".bad")) != "older damage" {
		t.Fatal("the older .bad file was replaced")
	}
	if err := s.SaveSettings(Settings{ActiveTab: "passphrase"}); err != nil {
		t.Fatalf("saving must still work: %v", err)
	}
}

func TestSaveSettingsKeepsOnlyWhatBelongs(t *testing.T) {
	dir := t.TempDir()
	s := &SageService{baseDir: dir}
	rec := "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq"
	err := s.SaveSettings(Settings{
		Recipients:     "# team\n" + rec + "\nmy secret passphrase",
		Identities:     `C:\keys\me.txt` + "\nanother passphrase",
		RecipientsFile: "hunter2",
	})
	if err != nil {
		t.Fatal(err)
	}
	saved := read(t, filepath.Join(dir, settingsFile))
	for _, gone := range []string{"my secret passphrase", "another passphrase", "hunter2"} {
		if strings.Contains(saved, gone) {
			t.Fatalf("%q was saved:\n%s", gone, saved)
		}
	}
	for _, kept := range []string{"# team", rec, `C:\\keys\\me.txt`} {
		if !strings.Contains(saved, kept) {
			t.Fatalf("%q was lost:\n%s", kept, saved)
		}
	}
}

func TestLongPathPrefix(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	cases := map[string]string{
		`C:\a\b`:         `\\?\C:\a\b`,
		`C:\a\.\b\..\c`:  `\\?\C:\a\c`,
		`\\srv\share\f`:  `\\?\UNC\srv\share\f`,
		`\\?\C:\already`: `\\?\C:\already`,
		`relative\path`:  `relative\path`,
	}
	for in, want := range cases {
		if got := longPath(in); got != want {
			t.Errorf("longPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBase64FilterKeepsLongPaths(t *testing.T) {
	path := `C:\Users\abcdefghijklmnopqrstuvwxyz0123456789abcdefgh\key.txt`
	if got := withoutSecrets(path); got != path {
		t.Fatalf("a long path was dropped: %q", got)
	}
	if !looksLikeBase64Blob("abcdefghijklmnopqrstuvwxyz0123456789abcdefgh") {
		t.Fatal("a bare 40+ character blob should be treated as possibly secret")
	}
}

var _ = time.Second
