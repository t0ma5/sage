package main

// The encryption core: parsing keys, naming outputs and processing one file.
// It has no GUI code, so it is tested directly by core_test.go.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"filippo.io/age/tag"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

const (
	recipientFileSizeLimit = 16 << 20 // same limits as the age CLI
	lineLengthLimit        = 8 << 10
	identityFileSizeLimit  = 16 << 20
)

// errNotSupported marks inputs that are valid age but that sage v1 cannot use yet.
var errNotSupported = errors.New("not supported in sage yet")

// ---------------------------------------------------------------- recipients

// recipientKind names a recipient line for the hint bar, or "" if it is not one.
func recipientKind(line string) string {
	switch {
	case strings.HasPrefix(line, "age1tag1"), strings.HasPrefix(line, "age1tagpq1"):
		return "age tagged key"
	case strings.HasPrefix(line, "age1pq1"):
		return "age post-quantum key"
	case strings.HasPrefix(line, "age1") && strings.Count(line, "1") > 1:
		return "age plugin key"
	case strings.HasPrefix(line, "age1"):
		return "age key"
	case strings.HasPrefix(line, "ssh-ed25519 "):
		return "SSH Ed25519 key"
	case strings.HasPrefix(line, "ssh-rsa "):
		return "SSH RSA key"
	}
	return ""
}

// parseRecipient follows the age CLI (cmd/age/parse.go), except that plugin
// recipients are refused: running plugin programs is not supported in sage yet.
func parseRecipient(s string) (age.Recipient, error) {
	switch {
	case strings.HasPrefix(s, "age1tag1") || strings.HasPrefix(s, "age1tagpq1"):
		return tag.ParseRecipient(s)
	case strings.HasPrefix(s, "age1pq1"):
		return age.ParseHybridRecipient(s)
	case strings.HasPrefix(s, "age1") && strings.Count(s, "1") > 1:
		return nil, fmt.Errorf("age plugin recipients are %w", errNotSupported)
	case strings.HasPrefix(s, "age1"):
		return age.ParseX25519Recipient(s)
	case strings.HasPrefix(s, "ssh-"):
		return agessh.ParseRecipient(s)
	}
	return nil, errors.New("not a recognised age or SSH public key")
}

// containsSecret reports whether a line holds a secret key, which must never be
// treated as a recipient or saved to the settings file.
func containsSecret(line string) bool {
	u := strings.ToUpper(line)
	return strings.Contains(u, "AGE-SECRET-KEY-") || strings.Contains(u, "AGE-PLUGIN-")
}

// keepLines applies withoutSecrets, then keeps only blank lines, # comments and
// lines that keep accepts. Anything else typed into a box (say, a passphrase pasted
// into the wrong one) is not written to the settings file.
func keepLines(text string, keep func(string) bool) string {
	var out []string
	for _, line := range strings.Split(withoutSecrets(text), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || keep(t) {
			out = append(out, line)
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func isRecipientLine(line string) bool { return recipientKind(line) != "" }

// looksLikePath: a Windows or relative path has a separator or a drive colon.
func looksLikePath(line string) bool {
	return strings.ContainsAny(line, `\/:`) && !looksLikeBase64Blob(line)
}

// meaningfulLines returns the lines that are neither blank nor # comments.
func meaningfulLines(text string) []string {
	var out []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// parseRecipientText parses the "Encrypt to" box. Any line that is not a usable
// recipient is an error: skipping it would create files that person cannot open.
// Line numbers count every line in the box, comments and blank lines included.
func parseRecipientText(text string) ([]age.Recipient, error) {
	var recs []age.Recipient
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if containsSecret(line) || strings.HasPrefix(line, "-----BEGIN") {
			return nil, errors.New("a secret key was pasted into 'Encrypt to'; use its public key (age1... or ssh-...) instead")
		}
		r, err := parseRecipient(line)
		if err != nil {
			if t, unsupported := unsupportedSSHKey(line); unsupported {
				return nil, fmt.Errorf("line %d: age can't encrypt to SSH keys of type %s; remove it or comment it out with #", i+1, t)
			}
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// parseRecipientsFile mirrors the age CLI's -R handling.
func parseRecipientsFile(name string) ([]age.Recipient, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open recipients file: %v", err)
	}
	defer f.Close()

	var recs []age.Recipient
	lr := &io.LimitedReader{R: f, N: recipientFileSizeLimit + 1}
	scanner := bufio.NewScanner(lr)
	n := 0
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if !utf8.ValidString(line) {
			return nil, fmt.Errorf("recipients file is not valid UTF-8")
		}
		if len(line) > lineLengthLimit {
			return nil, fmt.Errorf("recipients file: line %d is too long", n)
		}
		r, err := parseRecipient(line)
		if err != nil {
			if t, unsupported := unsupportedSSHKey(line); unsupported {
				// The age CLI skips these with a warning. sage refuses instead: a
				// skipped key is a person who can't open the file.
				return nil, fmt.Errorf("recipients file line %d: age can't encrypt to SSH keys of type %s; remove it or comment it out with #", n, t)
			}
			if errors.Is(err, errNotSupported) {
				return nil, fmt.Errorf("recipients file line %d: %v", n, err)
			}
			if strings.HasPrefix(line, "AGE-") {
				return nil, fmt.Errorf("recipients file line %d: this is a secret key, not a recipient", n)
			}
			// Like the age CLI, don't echo the line: it might be confidential.
			return nil, fmt.Errorf("recipients file: malformed recipient at line %d", n)
		}
		recs = append(recs, r)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read recipients file: %v", err)
	}
	if lr.N == 0 {
		return nil, errors.New("recipients file is too long")
	}
	if len(recs) == 0 {
		return nil, errors.New("no recipients found in the recipients file")
	}
	return recs, nil
}

// unsupportedSSHKey is copied from the age CLI: valid SSH public keys of a type age
// cannot encrypt to are skipped rather than treated as errors.
func unsupportedSSHKey(s string) (string, bool) {
	fields := strings.Split(s, " ")
	if len(fields) < 2 {
		return "", false
	}
	key, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", false
	}
	k := cryptobyte.String(key)
	var typeLen uint32
	var typeBytes []byte
	if !k.ReadUint32(&typeLen) || !k.ReadBytes(&typeBytes, int(typeLen)) {
		return "", false
	}
	if t := fields[0]; t == string(typeBytes) {
		switch t {
		case "ssh-ed25519":
			return "", false
		case "ssh-rsa":
			out, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
			if err != nil {
				return "", false
			}
			cryptoKey, ok := out.(ssh.CryptoPublicKey)
			if !ok {
				return "", false
			}
			rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
			if !ok {
				return "", false
			}
			return t, rsaKey.N.BitLen() < 2048
		default:
			return t, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------- identities

// parseIdentityFile reads one identity file: native age keys (X25519 or
// post-quantum) or an unencrypted SSH private key.
func parseIdentityFile(name string) ([]age.Identity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open identity file: %v", err)
	}
	defer f.Close()

	b := bufio.NewReader(f)
	p, _ := b.Peek(1024 + len(armor.Header))
	trimmed := bytes.TrimSpace(p)
	base := filepath.Base(name)

	switch {
	case bytes.HasPrefix(p, []byte("age-encryption")) || bytes.HasPrefix(trimmed, []byte(armor.Header)):
		return nil, fmt.Errorf("%q is a passphrase-protected identity file, which is %w", base, errNotSupported)

	case bytes.HasPrefix(trimmed, []byte("-----BEGIN")):
		const sshKeySizeLimit = 1 << 14
		contents, err := io.ReadAll(io.LimitReader(b, sshKeySizeLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %v", base, err)
		}
		id, err := agessh.ParseIdentity(contents)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, fmt.Errorf("%q is a passphrase-protected SSH key, which is %w", base, errNotSupported)
		}
		if err != nil {
			return nil, fmt.Errorf("%q is not a usable SSH private key: %v", base, err)
		}
		return []age.Identity{id}, nil
	}

	var ids []age.Identity
	lr := &io.LimitedReader{R: b, N: identityFileSizeLimit + 1}
	scanner := bufio.NewScanner(lr)
	n := 0
	for scanner.Scan() {
		n++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		var id age.Identity
		switch {
		case strings.HasPrefix(line, "AGE-SECRET-KEY-PQ-1"):
			id, err = age.ParseHybridIdentity(line)
		case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
			id, err = age.ParseX25519Identity(line)
		case strings.HasPrefix(line, "AGE-PLUGIN-"):
			err = fmt.Errorf("age plugin identities are %w", errNotSupported)
		case strings.HasPrefix(line, "age1"):
			err = errors.New("this is a public key (recipient), not a secret key")
		default:
			err = errors.New("unknown identity type")
		}
		if err != nil {
			return nil, fmt.Errorf("%q line %d: %v", base, n, err)
		}
		ids = append(ids, id)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", base, err)
	}
	if lr.N == 0 {
		return nil, fmt.Errorf("%q is too long", base)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities found in %q", base)
	}
	return ids, nil
}

// ---------------------------------------------------------------- output names

// nameCandidates yields path, then "name (1).ext", "name (2).ext", ... keeping a
// trailing .age last: "a.txt.age" is followed by "a (1).txt.age".
func nameCandidates(path string, yield func(string) bool) {
	isAge := strings.HasSuffix(strings.ToLower(path), ".age")
	base := path
	if isAge {
		base = path[:len(path)-4]
	}
	ext := extensionOf(base)
	stem := strings.TrimSuffix(base, ext)
	suffix := ""
	if isAge {
		suffix = path[len(path)-4:]
	}
	if !yield(path) {
		return
	}
	for i := 1; ; i++ {
		if !yield(fmt.Sprintf("%s (%d)%s%s", stem, i, ext, suffix)) {
			return
		}
	}
}

// extensionOf is filepath.Ext with two fixes for numbering: "x.tar.gz" keeps
// ".tar.gz" together (-> "x (1).tar.gz"), and a name that only starts with a dot,
// like ".gitignore", has no extension (-> ".gitignore (1)").
func extensionOf(path string) string {
	name := filepath.Base(path)
	lower := strings.ToLower(name)
	for _, double := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz", ".tar.lzma"} {
		if strings.HasSuffix(lower, double) && len(name) > len(double) {
			return name[len(name)-len(double):]
		}
	}
	ext := filepath.Ext(name)
	if ext == name { // ".gitignore": the dot starts the name, it isn't an extension
		return ""
	}
	return ext
}

// decryptedName turns "x.txt.age" into "x.txt"; a file named exactly ".age"
// becomes ".age.decrypted".
func decryptedName(path string) string {
	if strings.HasSuffix(strings.ToLower(path), ".age") && len(filepath.Base(path)) > 4 {
		return path[:len(path)-4]
	}
	return path + ".decrypted"
}

// createPartFile creates and opens "<final>.part" (or "<final>.N.part")
// exclusively. Output goes there first; a crash leaves an obvious .part file,
// never a truncated file under the real name.
func createPartFile(final string) (string, *os.File, error) {
	for i := 0; ; i++ {
		candidate := final + ".part"
		if i > 0 {
			candidate = fmt.Sprintf("%s.%d.part", final, i)
		}
		f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return candidate, f, nil
		}
		if !os.IsExist(err) {
			return "", nil, err
		}
	}
}

// publishPartFile renames the finished .part file to the first free name.
// renameNoReplace fails when the target exists, so even a file that appeared
// while the job ran is never overwritten.
func publishPartFile(part, final string) (string, error) {
	var result string
	var resultErr error
	nameCandidates(final, func(candidate string) bool {
		err := renameNoReplace(part, candidate)
		if err == nil {
			result = candidate
			return false
		}
		if os.IsExist(err) {
			return true // name taken: try the next one
		}
		resultErr = err
		return false
	})
	return result, resultErr
}

// ---------------------------------------------------------------- processing

// ctxReader stops a copy as soon as the job is cancelled.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
	n   func(int)
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(p)
	if c.n != nil && n > 0 {
		c.n(n)
	}
	return n, err
}

// encryptStream writes src encrypted to dst.
func encryptStream(ctx context.Context, dst io.Writer, src io.Reader, recipients []age.Recipient, useArmor bool, progress func(int)) error {
	out := dst
	var armorWriter io.WriteCloser
	if useArmor {
		armorWriter = armor.NewWriter(dst)
		out = armorWriter
	}
	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, &ctxReader{ctx: ctx, r: src, n: progress}); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if armorWriter != nil {
		return armorWriter.Close()
	}
	return nil
}

// decryptStream writes src decrypted to dst, accepting binary or armored input.
func decryptStream(ctx context.Context, dst io.Writer, src io.Reader, identities []age.Identity, progress func(int)) error {
	in := &ctxReader{ctx: ctx, r: src, n: progress}
	b := bufio.NewReader(in)
	var r io.Reader = b
	if p, _ := b.Peek(len(armor.Header) + 1024); bytes.HasPrefix(bytes.TrimSpace(p), []byte(armor.Header)) {
		r = armor.NewReader(b)
	}
	plain, err := age.Decrypt(r, identities...)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, plain)
	return err
}

// friendlyError turns library errors into one short line for the log.
func friendlyError(err error) string {
	var noMatch *age.NoIdentityMatchError
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.As(err, &noMatch):
		return "wrong passphrase, or none of the identities can open this file"
	}
	msg := err.Error()
	if strings.Contains(msg, "incorrect identity") || strings.Contains(msg, "incorrect passphrase") {
		return "wrong passphrase or altered file"
	}
	return msg
}

// isWrongKey reports a failure caused by the passphrase or identities, as opposed
// to an unreadable or damaged file.
func isWrongKey(err error) bool {
	var noMatch *age.NoIdentityMatchError
	return errors.As(err, &noMatch)
}

// processFile encrypts or decrypts one file next to itself and returns the output
// path. The output never replaces an existing file.
func processFile(ctx context.Context, path string, encrypt bool, recipients []age.Recipient,
	identities []age.Identity, useArmor bool, progress func(int)) (string, error) {

	src, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer src.Close()

	final := decryptedName(path)
	if encrypt {
		final = path + ".age"
	}
	part, out, err := createPartFile(final)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			out.Close()
			_ = retryWhileLocked(func() error { return os.Remove(part) })
		}
	}()

	bw := bufio.NewWriterSize(out, 1<<20)
	if encrypt {
		err = encryptStream(ctx, bw, src, recipients, useArmor, progress)
	} else {
		err = decryptStream(ctx, bw, src, identities, progress)
	}
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	published, err := publishPartFile(part, final)
	if err != nil {
		return "", err
	}
	ok = true
	return published, nil
}

// ---------------------------------------------------------------- file list

// expandPaths turns dropped or chosen paths into absolute file paths. A folder
// adds the files directly inside it (following links to files); subfolders are
// not included and are counted, so the window can say so.
func expandPaths(paths []string) (files []string, skippedDirs int) {
	var out []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			out = append(out, abs)
			continue
		}
		entries, err := os.ReadDir(abs)
		if err != nil {
			continue
		}
		var names []string
		for _, e := range entries {
			fi, err := os.Stat(filepath.Join(abs, e.Name())) // follows links
			switch {
			case err != nil:
			case fi.Mode().IsRegular():
				names = append(names, e.Name())
			case fi.IsDir():
				skippedDirs++
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, filepath.Join(abs, n))
		}
	}
	return out, skippedDirs
}

// mergeFiles adds new files to the list. If any .age file is present, the list
// becomes decrypt-only and other files are dropped (and counted).
func mergeFiles(existing, added []string) (files []string, mode string, ignored, duplicates int) {
	seen := map[string]bool{}
	for _, f := range append(append([]string{}, existing...), added...) {
		key := strings.ToLower(filepath.Clean(f))
		if seen[key] {
			duplicates++
			continue
		}
		seen[key] = true
		files = append(files, f)
	}
	duplicates -= countDuplicatesWithin(existing)

	hasAge := false
	for _, f := range files {
		if isAgeFile(f) {
			hasAge = true
			break
		}
	}
	if !hasAge {
		if len(files) == 0 {
			return files, "", 0, duplicates
		}
		return files, "encrypt", 0, duplicates
	}
	var kept []string
	for _, f := range files {
		if isAgeFile(f) {
			kept = append(kept, f)
		} else {
			ignored++
		}
	}
	return kept, "decrypt", ignored, duplicates
}

func countDuplicatesWithin(list []string) int {
	seen := map[string]bool{}
	d := 0
	for _, f := range list {
		key := strings.ToLower(filepath.Clean(f))
		if seen[key] {
			d++
		}
		seen[key] = true
	}
	return d
}

func isAgeFile(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".age")
}
