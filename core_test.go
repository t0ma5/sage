package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func noPartFiles(t *testing.T, dir string) {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "*.part"))
	if len(m) > 0 {
		t.Fatalf("leftover .part files: %v", m)
	}
}

func scryptPair(t *testing.T, pass string) (age.Recipient, age.Identity) {
	t.Helper()
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkFactor(10) // fast tests; the app uses age's default
	i, err := age.NewScryptIdentity(pass)
	if err != nil {
		t.Fatal(err)
	}
	return r, i
}

func TestPassphraseRoundTripAndNaming(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.txt")
	write(t, src, "hello sage\n")
	r, i := scryptPair(t, "pässwörd x")

	out, err := processFile(context.Background(), src, true, []age.Recipient{r}, nil, false, nil)
	if err != nil || out != src+".age" {
		t.Fatalf("encrypt: %v %q", err, out)
	}
	// Second encryption must not overwrite: "a (1).txt.age".
	out2, err := processFile(context.Background(), src, true, []age.Recipient{r}, nil, false, nil)
	if err != nil || filepath.Base(out2) != "a (1).txt.age" {
		t.Fatalf("second encrypt: %v %q", err, out2)
	}
	// Decrypt next to the original, which exists: "a (1).txt".
	dec, err := processFile(context.Background(), out, false, nil, []age.Identity{i}, false, nil)
	if err != nil || filepath.Base(dec) != "a (1).txt" {
		t.Fatalf("decrypt: %v %q", err, dec)
	}
	if read(t, dec) != "hello sage\n" || read(t, src) != "hello sage\n" {
		t.Fatal("content mismatch or original changed")
	}
	noPartFiles(t, dir)
}

func TestWrongPassphraseLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "b.txt")
	write(t, src, "x")
	r, _ := scryptPair(t, "right")
	enc, err := processFile(context.Background(), src, true, []age.Recipient{r}, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, wrong := scryptPair(t, "wrong")
	_, err = processFile(context.Background(), enc, false, nil, []age.Identity{wrong}, false, nil)
	if err == nil || !isWrongKey(err) {
		t.Fatalf("expected a wrong-key error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "b (1).txt")); statErr == nil {
		t.Fatal("failed decrypt left an output file")
	}
	noPartFiles(t, dir)
}

func TestCancelLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "big.bin")
	write(t, src, strings.Repeat("z", 4<<20))
	r, _ := scryptPair(t, "p")
	ctx, cancel := context.WithCancel(context.Background())
	_, err := processFile(ctx, src, true, []age.Recipient{r}, nil, false, func(int) { cancel() })
	if err == nil {
		t.Fatal("expected cancellation")
	}
	if _, statErr := os.Stat(src + ".age"); statErr == nil {
		t.Fatal("cancelled job left an output file")
	}
	noPartFiles(t, dir)
}

func TestRecipientsAndArmor(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "c.txt")
	write(t, src, "multi\n")
	x1, _ := age.GenerateX25519Identity()
	x2, _ := age.GenerateX25519Identity()
	pq1, _ := age.GenerateHybridIdentity()
	pq2, _ := age.GenerateHybridIdentity()

	// Two classic recipients, then two post-quantum ones; each key opens the file.
	for _, group := range [][]interface{ String() string }{{x1, x2}, {pq1, pq2}} {
		var lines []string
		var secrets []string
		for _, id := range group {
			switch v := id.(type) {
			case *age.X25519Identity:
				lines, secrets = append(lines, v.Recipient().String()), append(secrets, v.String())
			case *age.HybridIdentity:
				lines, secrets = append(lines, v.Recipient().String()), append(secrets, v.String())
			}
		}
		recs, err := parseRecipientText("# Alice\n" + lines[0] + "\n\n" + lines[1] + "\n")
		if err != nil || len(recs) != 2 {
			t.Fatalf("parse: %v %d", err, len(recs))
		}
		enc, err := processFile(context.Background(), src, true, recs, nil, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(read(t, enc), "-----BEGIN AGE ENCRYPTED FILE-----") {
			t.Fatal("not armored")
		}
		for n, secret := range secrets {
			keyFile := filepath.Join(dir, "key.txt")
			write(t, keyFile, "# created: test\n"+secret+"\n")
			ids, err := parseIdentityFile(keyFile)
			if err != nil {
				t.Fatal(err)
			}
			dec, err := processFile(context.Background(), enc, false, nil, ids, false, nil)
			if err != nil || read(t, dec) != "multi\n" {
				t.Fatalf("identity %d: %v", n, err)
			}
			os.Remove(dec)
		}
		os.Remove(enc)
	}

	// Mixing the two kinds is refused up front, with a clear reason.
	svc := &SageService{}
	_, _, err := svc.recipientsFor(Request{Recipients: x1.Recipient().String() + "\n" + pq1.Recipient().String()})
	if err == nil || !strings.Contains(err.Error(), "can't be mixed") {
		t.Fatalf("mixed recipients: %v", err)
	}
}

func TestSSHIdentity(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "id_ed25519")
	write(t, keyFile, string(pem.EncodeToMemory(block)))
	sshPub, _ := ssh.NewPublicKey(pub)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	recs, err := parseRecipientText(line)
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "d.txt")
	write(t, src, "ssh\n")
	enc, err := processFile(context.Background(), src, true, recs, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := parseIdentityFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := processFile(context.Background(), enc, false, nil, ids, false, nil)
	if err != nil || read(t, dec) != "ssh\n" {
		t.Fatalf("ssh round trip: %v", err)
	}
}

func TestRecipientErrors(t *testing.T) {
	x, _ := age.GenerateX25519Identity()
	cases := map[string]string{
		"garbage":                       "not a recognised",
		x.String():                      "secret key",
		"age1yubikey1qwertyuiopasdfgh1": "plugin",
	}
	for input, want := range cases {
		_, err := parseRecipientText(x.Recipient().String() + "\n" + input)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", input, err, want)
		}
	}
}

func TestEncryptedIdentityFileReported(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.age")
	write(t, keyFile, "age-encryption.org/v1\n-> scrypt abc 18\n")
	_, err := parseIdentityFile(keyFile)
	if err == nil || !strings.Contains(err.Error(), "passphrase-protected") {
		t.Fatalf("got %v", err)
	}
}

func TestMergeFiles(t *testing.T) {
	files, mode, ignored, dups := mergeFiles([]string{`C:\a.txt`}, []string{`C:\b.txt`, `c:\A.TXT`})
	if len(files) != 2 || mode != "encrypt" || ignored != 0 || dups != 1 {
		t.Fatalf("append: %v %s %d %d", files, mode, ignored, dups)
	}
	files, mode, ignored, _ = mergeFiles(files, []string{`C:\x.age`})
	if len(files) != 1 || mode != "decrypt" || ignored != 2 {
		t.Fatalf("age switch: %v %s %d", files, mode, ignored)
	}
}

func TestNameCandidates(t *testing.T) {
	var got []string
	nameCandidates(`C:\d\a.txt.age`, func(s string) bool { got = append(got, filepath.Base(s)); return len(got) < 3 })
	want := []string{"a.txt.age", "a (1).txt.age", "a (2).txt.age"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v", got)
	}
	if decryptedName(`C:\d\.age`) != `C:\d\.age.decrypted` {
		t.Fatal("dot-age name")
	}
}

func TestSettingsNeverStoreSecrets(t *testing.T) {
	x, _ := age.GenerateX25519Identity()
	got := withoutSecrets("# me\n" + x.Recipient().String() + "\n" + x.String())
	if strings.Contains(got, "AGE-SECRET-KEY") || !strings.Contains(got, x.Recipient().String()) {
		t.Fatalf("got %q", got)
	}
}

// Interoperability with the official age CLI, when it is available.
func ageCLI(t *testing.T) string {
	t.Helper()
	p := os.Getenv("SAGE_TEST_AGE")
	if p == "" {
		p, _ = exec.LookPath("age")
	}
	if _, err := os.Stat(p); err != nil {
		// Skipping silently would let a CI run look green without interop coverage.
		if os.Getenv("SAGE_REQUIRE_INTEROP") != "" {
			t.Fatalf("age CLI not found at %s (SAGE_REQUIRE_INTEROP is set)", p)
		}
		t.Skip("age CLI not found; set SAGE_TEST_AGE, or SAGE_REQUIRE_INTEROP=1 to make this fail")
	}
	return p
}

func TestInteropWithAgeCLI(t *testing.T) {
	cli := ageCLI(t)
	dir := t.TempDir()
	x, _ := age.GenerateX25519Identity()
	keyFile := filepath.Join(dir, "key.txt")
	write(t, keyFile, x.String()+"\n")

	// sage encrypts -> age CLI decrypts.
	src := filepath.Join(dir, "e.txt")
	write(t, src, "interop\n")
	enc, err := processFile(context.Background(), src, true, []age.Recipient{x.Recipient()}, nil, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(cli, "-d", "-i", keyFile, enc).Output()
	if err != nil || string(out) != "interop\n" {
		t.Fatalf("age CLI could not decrypt sage output: %v %q", err, out)
	}

	// age CLI encrypts -> sage decrypts.
	cliEnc := filepath.Join(dir, "f.txt.age")
	if err := exec.Command(cli, "-r", x.Recipient().String(), "-o", cliEnc, src).Run(); err != nil {
		t.Fatal(err)
	}
	ids, _ := parseIdentityFile(keyFile)
	dec, err := processFile(context.Background(), cliEnc, false, nil, ids, false, nil)
	if err != nil || read(t, dec) != "interop\n" {
		t.Fatalf("sage could not decrypt age CLI output: %v", err)
	}
}

func TestInteropPassphraseWithAgeCLI(t *testing.T) {
	cli := ageCLI(t)
	plugin := filepath.Join(filepath.Dir(cli), "age-plugin-batchpass.exe")
	if _, err := os.Stat(plugin); err != nil {
		t.Skip("age-plugin-batchpass not found")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "g.txt")
	write(t, src, "pass interop\n")
	r, err := age.NewScryptRecipient("pässwörd x") // default work factor, like the app
	if err != nil {
		t.Fatal(err)
	}
	enc, err := processFile(context.Background(), src, true, []age.Recipient{r}, nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cli, "-d", "-j", "batchpass", enc)
	cmd.Env = append(os.Environ(), "AGE_PASSPHRASE=pässwörd x", "PATH="+filepath.Dir(cli)+";"+os.Getenv("PATH"))
	out, err := cmd.Output()
	if err != nil || string(out) != "pass interop\n" {
		t.Fatalf("age CLI could not decrypt sage passphrase output: %v %q", err, out)
	}
}

func TestWriteNewIdentityNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.txt")
	kp, err := writeNewIdentity(path, true)
	if err != nil || !strings.HasPrefix(kp.PublicKey, "age1pq1") {
		t.Fatalf("%v %q", err, kp.PublicKey)
	}
	before := read(t, path)
	if _, err := writeNewIdentity(path, false); err == nil {
		t.Fatal("overwrote an existing key file")
	}
	if read(t, path) != before {
		t.Fatal("key file changed")
	}
	if _, err := parseIdentityFile(path); err != nil {
		t.Fatalf("generated key file not readable: %v", err)
	}
}
