package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// encryptWith writes name in dir and encrypts it with a fast scrypt passphrase.
func encryptWith(t *testing.T, dir, name, content, pass string) string {
	t.Helper()
	src := filepath.Join(dir, name)
	write(t, src, content)
	r, _ := scryptPair(t, pass)
	out, err := processFile(context.Background(), src, true, []age.Recipient{r}, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(src)
	return out
}

func identityFor(t *testing.T, pass string) []age.Identity {
	t.Helper()
	_, i := scryptPair(t, pass)
	return []age.Identity{i}
}

func TestRunContinuesAfterLaterWrongKey(t *testing.T) {
	dir := t.TempDir()
	a := encryptWith(t, dir, "a.txt", "A", "one")
	b := encryptWith(t, dir, "b.txt", "B", "two") // different passphrase
	c := encryptWith(t, dir, "c.txt", "C", "one")

	done := (&SageService{}).run(context.Background(), []string{a, b, c}, false, nil, identityFor(t, "one"), false)

	if read(t, filepath.Join(dir, "a.txt")) != "A" || read(t, filepath.Join(dir, "c.txt")) != "C" {
		t.Fatal("a and c should be decrypted")
	}
	if len(done.Remaining) != 1 || done.Remaining[0] != b {
		t.Fatalf("only b should remain, got %v", done.Remaining)
	}
	if !strings.HasPrefix(done.Summary, "Finished: 2 OK, 1 failed") {
		t.Fatalf("summary %q", done.Summary)
	}
	noPartFiles(t, dir)
}

func TestRunStopsOnFirstWrongKeyAndOrdersRetry(t *testing.T) {
	dir := t.TempDir()
	a := encryptWith(t, dir, "a.txt", "A", "one")
	b := encryptWith(t, dir, "b.txt", "B", "one")
	c := encryptWith(t, dir, "c.txt", "C", "one")

	done := (&SageService{}).run(context.Background(), []string{a, b, c}, false, nil, identityFor(t, "wrong"), false)

	if !strings.Contains(done.Summary, "0 OK, 1 failed, 2 not processed") {
		t.Fatalf("summary %q", done.Summary)
	}
	// Unprocessed first, the failed one last, so a retry handles the others first.
	if strings.Join(done.Remaining, "|") != strings.Join([]string{b, c, a}, "|") {
		t.Fatalf("remaining order %v", done.Remaining)
	}
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Fatalf("%s should not exist after a wrong passphrase", n)
		}
	}
	noPartFiles(t, dir)
}

func TestRunCancelled(t *testing.T) {
	dir := t.TempDir()
	a := encryptWith(t, dir, "a.txt", "A", "one")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := (&SageService{}).run(ctx, []string{a}, false, nil, identityFor(t, "one"), false)
	if !strings.Contains(done.Summary, "not processed (cancelled)") || len(done.Remaining) != 1 {
		t.Fatalf("%+v", done)
	}
}

func TestStatus(t *testing.T) {
	s := &SageService{}
	dir := t.TempDir()
	plain := filepath.Join(dir, "x.txt")
	ageFile := filepath.Join(dir, "x.txt.age")
	write(t, plain, "x")
	write(t, ageFile, "x")
	info := func(set, confirm, match, lb bool) *PassInfo {
		return &PassInfo{Set: set, ConfirmSet: confirm, Match: match, LineBreak: lb}
	}

	cases := []struct {
		name    string
		r       Request
		enabled bool
		hint    string
	}{
		{"no files", Request{}, false, "Drop files"},
		{"needs passphrase", Request{Files: []string{plain}, PassInfo: info(false, false, true, false)}, false, "Enter the passphrase"},
		{"needs confirm", Request{Files: []string{plain}, PassInfo: info(true, false, false, false)}, false, "Repeat"},
		{"mismatch", Request{Files: []string{plain}, PassInfo: info(true, true, false, false)}, false, "do not match"},
		{"line break", Request{Files: []string{plain}, PassInfo: info(true, true, true, true)}, false, "line break"},
		{"ready", Request{Files: []string{plain}, PassInfo: info(true, true, true, false)}, true, "Ready"},
		// The window claims "encrypt" with an empty confirm field, but the file is
		// an .age file: Go decides it is a decrypt, which needs no confirmation.
		{"mode from files", Request{Files: []string{ageFile}, Mode: "encrypt", PassInfo: info(true, false, false, false)}, true, "Ready"},
		{"real passphrase wins", Request{Files: []string{plain}, Passphrase: "a", Confirm: "b", PassInfo: info(true, true, true, false)}, false, "do not match"},
	}
	for _, c := range cases {
		st := s.Status(c.r)
		if st.Enabled != c.enabled || !strings.Contains(st.Hint, c.hint) {
			t.Errorf("%s: got %+v", c.name, st)
		}
	}
	if st := s.Status(Request{Files: []string{ageFile}}); !strings.HasPrefix(st.Button, "Decrypt") {
		t.Errorf("button %q", st.Button)
	}
}

func TestStatusRecipientTab(t *testing.T) {
	s := &SageService{}
	dir := t.TempDir()
	plain := filepath.Join(dir, "x.txt")
	write(t, plain, "x")
	x, _ := age.GenerateX25519Identity()
	pq, _ := age.GenerateHybridIdentity()

	st := s.Status(Request{Files: []string{plain}, Tab: "recipient", Recipients: "# me\n" + x.Recipient().String()})
	if !st.Enabled || !strings.Contains(st.Hint, "1 recipient(s) (age key)") {
		t.Fatalf("%+v", st)
	}
	st = s.Status(Request{Files: []string{plain}, Tab: "recipient",
		Recipients: x.Recipient().String() + "\n" + pq.Recipient().String()})
	if st.Enabled || !strings.Contains(st.Hint, "can't be mixed") {
		t.Fatalf("mixed: %+v", st)
	}
	// Line numbers count comment and blank lines too.
	st = s.Status(Request{Files: []string{plain}, Tab: "recipient", Recipients: "# a\n\n" + x.Recipient().String() + "\nnonsense"})
	if st.Enabled || !strings.Contains(st.Hint, "line 4") {
		t.Fatalf("line number: %+v", st)
	}
}

func ecdsaAuthorizedKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func TestParseRecipientsFile(t *testing.T) {
	dir := t.TempDir()
	x, _ := age.GenerateX25519Identity()
	path := filepath.Join(dir, "recipients.txt")

	write(t, path, "# Alice\r\n"+x.Recipient().String()+"\r\n\r\n")
	recs, err := parseRecipientsFile(path)
	if err != nil || len(recs) != 1 {
		t.Fatalf("CRLF file: %v %d", err, len(recs))
	}

	write(t, path, x.Recipient().String()+"\n"+ecdsaAuthorizedKey(t)+"\n")
	if _, err := parseRecipientsFile(path); err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "ecdsa") {
		t.Fatalf("unusable SSH key must be refused, got %v", err)
	}

	write(t, path, x.String()+"\n")
	if _, err := parseRecipientsFile(path); err == nil || !strings.Contains(err.Error(), "secret key") {
		t.Fatalf("secret key in recipients file: %v", err)
	}

	write(t, path, "# only comments\n")
	if _, err := parseRecipientsFile(path); err == nil {
		t.Fatal("empty recipients file must be an error")
	}

	if _, err := parseRecipientText(ecdsaAuthorizedKey(t)); err == nil || !strings.Contains(err.Error(), "ecdsa") {
		t.Fatalf("unusable SSH key in the box: %v", err)
	}
}

func TestPublishNeverOverwritesALateFile(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "a.txt")
	part, f, err := createPartFile(final)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("new")
	f.Close()
	write(t, final, "someone else's file") // appears while the job runs
	got, err := publishPartFile(part, final)
	if err != nil || filepath.Base(got) != "a (1).txt" {
		t.Fatalf("%v %q", err, got)
	}
	if read(t, final) != "someone else's file" || read(t, got) != "new" {
		t.Fatal("existing file was touched")
	}
	noPartFiles(t, dir)
}

func TestDamagedInputLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	enc := encryptWith(t, dir, "d.txt", strings.Repeat("data", 50000), "p")
	b, _ := os.ReadFile(enc)
	write(t, enc, string(b[:len(b)-100])) // truncated
	_, err := processFile(context.Background(), enc, false, nil, identityFor(t, "p"), false, nil)
	if err == nil {
		t.Fatal("truncated file decrypted without error")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "d.txt")); statErr == nil {
		t.Fatal("damaged input left an output file")
	}
	noPartFiles(t, dir)
}

func TestInspect(t *testing.T) {
	dir := t.TempDir()
	pass := encryptWith(t, dir, "p.txt", "x", "p")
	if out := inspectFile(pass); !strings.Contains(out, "scrypt") || !strings.Contains(out, "Uses post-quantum") {
		t.Fatalf("passphrase file: %s", out)
	}
	x, _ := age.GenerateX25519Identity()
	src := filepath.Join(dir, "k.txt")
	write(t, src, "x")
	enc, _ := processFile(context.Background(), src, true, []age.Recipient{x.Recipient()}, nil, true, nil)
	if out := inspectFile(enc); !strings.Contains(out, "X25519") || !strings.Contains(out, "NOT use post-quantum") || !strings.Contains(out, "armored") {
		t.Fatalf("X25519 armored file: %s", out)
	}
	notAge := filepath.Join(dir, "fake.age")
	write(t, notAge, "hello")
	if out := inspectFile(notAge); !strings.Contains(out, "not a valid age file") {
		t.Fatalf("fake file: %s", out)
	}
}

func TestExpandPaths(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "b.txt"), "b")
	write(t, filepath.Join(dir, "a.txt"), "a")
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	write(t, filepath.Join(dir, "sub", "c.txt"), "c")
	got, skipped := expandPaths([]string{dir, filepath.Join(dir, "missing")})
	if len(got) != 2 || filepath.Base(got[0]) != "a.txt" || filepath.Base(got[1]) != "b.txt" {
		t.Fatalf("folder should add its own files, sorted, no subfolders: %v", got)
	}
	if skipped != 1 {
		t.Fatalf("one subfolder should be reported as skipped, got %d", skipped)
	}
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir)
	if got, _ := expandPaths([]string{"a.txt"}); len(got) != 1 || !filepath.IsAbs(got[0]) {
		t.Fatalf("relative path not made absolute: %v", got)
	}
}

func TestLongPath(t *testing.T) {
	dir := t.TempDir()
	deep := dir
	for len(deep) < 300 {
		deep = filepath.Join(deep, strings.Repeat("d", 40))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(deep, "long.txt")
	write(t, src, "long path")
	r, i := scryptPair(t, "p")
	enc, err := processFile(context.Background(), src, true, []age.Recipient{r}, nil, false, nil)
	if err != nil || len(enc) < 260 {
		t.Fatalf("encrypt in a %d-character path: %v", len(src), err)
	}
	write(t, src, "taken") // force the decrypt to be renamed to "long (1).txt"
	dec, err := processFile(context.Background(), enc, false, nil, []age.Identity{i}, false, nil)
	if err != nil || filepath.Base(dec) != "long (1).txt" || read(t, dec) != "long path" {
		t.Fatalf("decrypt: %v %q", err, dec)
	}
}

func TestExtensionOfNumbering(t *testing.T) {
	cases := map[string]string{
		`C:\d\x.tar.gz`:     "x (1).tar.gz",
		`C:\d\.gitignore`:   ".gitignore (1)",
		`C:\d\report.docx`:  "report (1).docx",
		`C:\d\noext`:        "noext (1)",
		`C:\d\x.tar.gz.age`: "x (1).tar.gz.age",
	}
	for in, want := range cases {
		var second string
		n := 0
		nameCandidates(in, func(s string) bool { n++; second = s; return n < 2 })
		if filepath.Base(second) != want {
			t.Errorf("%s: got %q, want %q", in, filepath.Base(second), want)
		}
	}
}

func TestWithoutSecretsDropsPEMKeys(t *testing.T) {
	x, _ := age.GenerateX25519Identity()
	text := strings.Join([]string{
		"# work laptop",
		`C:\keys\me.txt`,
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
		"QyNTUxOQAAACDzbXq9xLzv1/8+ExampleExampleExampleExampleExample==",
		"-----END OPENSSH PRIVATE KEY-----",
		x.String(),
		"QyNTUxOQAAACDzbXq9xLzv1/8+ExampleExampleExampleExampleStray",
		x.Recipient().String(),
	}, "\n")
	got := withoutSecrets(text)
	if strings.Contains(got, "PRIVATE KEY") || strings.Contains(got, "b3BlbnNz") || strings.Contains(got, "QyNTUx") || strings.Contains(got, "AGE-SECRET") {
		t.Fatalf("secret material kept:\n%s", got)
	}
	for _, keep := range []string{"# work laptop", `C:\keys\me.txt`, x.Recipient().String()} {
		if !strings.Contains(got, keep) {
			t.Fatalf("lost %q:\n%s", keep, got)
		}
	}
}

func TestDamagedSettingsAreKept(t *testing.T) {
	dir := t.TempDir()
	s := &SageService{baseDir: dir}
	write(t, filepath.Join(dir, settingsFile), `{"recipients": "age1abc", broken`)
	st := s.LoadSettings()
	if st.Notice == "" || st.Recipients != "" {
		t.Fatalf("%+v", st)
	}
	if !strings.Contains(read(t, filepath.Join(dir, settingsFile+".bad")), "age1abc") {
		t.Fatal("damaged file not kept as .bad")
	}
	if err := s.SaveSettings(Settings{ActiveTab: "recipient", Recipients: "age1new"}); err != nil {
		t.Fatal(err)
	}
	var saved Settings
	json.Unmarshal([]byte(read(t, filepath.Join(dir, settingsFile))), &saved)
	if saved.Recipients != "age1new" || saved.Notice != "" {
		t.Fatalf("saved %+v", saved)
	}
}

func TestSettingsWithByteOrderMark(t *testing.T) {
	dir := t.TempDir()
	s := &SageService{baseDir: dir}
	write(t, filepath.Join(dir, settingsFile), "\xef\xbb\xbf"+`{"activeTab": "recipient", "recipients": "age1abc"}`)
	st := s.LoadSettings()
	if st.Notice != "" || st.ActiveTab != "recipient" || st.Recipients != "age1abc" {
		t.Fatalf("a BOM must not count as damage: %+v", st)
	}
}

func TestNewIdentityInNumbersFiles(t *testing.T) {
	dir := t.TempDir()
	first, err := newIdentityIn(dir, false)
	if err != nil || filepath.Base(first.Path) != "age-key.txt" {
		t.Fatalf("%v %q", err, first.Path)
	}
	second, err := newIdentityIn(dir, true)
	if err != nil || filepath.Base(second.Path) != "age-key (1).txt" {
		t.Fatalf("%v %q", err, second.Path)
	}
	if first.PublicKey == second.PublicKey {
		t.Fatal("same key twice")
	}
}
