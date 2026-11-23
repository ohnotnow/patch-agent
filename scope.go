package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// defaultScanPaths are the places walked in full on every run. Everything
// else under "/" is excluded from the walk.
var defaultScanPaths = []string{
	// what syft reads to identify the distro
	"/etc/os-release",
	"/etc/system-release-cpe",
	"/etc/redhat-release",
	// OS package databases
	"/var/lib/dpkg",
	"/var/lib/rpm",
	// installed programs and libraries, packaged or not. On most current
	// distros /bin, /sbin, /lib and /lib64 are symlinks into /usr.
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
	// where software outside the package manager usually lives
	"/opt",
	"/srv",
	"/export",
}

// localFSTypes is an allowlist: only these filesystem types are walked.
// Network filesystems, autofs trigger points and anything unrecognised are
// skipped and reported.
var localFSTypes = map[string]bool{
	"ext2":     true,
	"ext3":     true,
	"ext4":     true,
	"xfs":      true,
	"btrfs":    true,
	"zfs":      true,
	"f2fs":     true,
	"bcachefs": true,
}

type mount struct {
	Point  string
	FSType string
}

type skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// scope is the plan for one scan: what is walked, what was left out and why,
// and the syft exclude patterns (relative to the scan root) that enforce it.
type scope struct {
	Walk     []string
	Skipped  []skipped
	Excludes []string
}

// parseMountinfo reads /proc/self/mountinfo. Reading it touches no mount.
func parseMountinfo(r io.Reader) ([]mount, error) {
	var mounts []mount
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		// "<id> <parent> <dev> <root> <mount point> <options> [optional...] - <fstype> <source> <superopts>"
		before, after, found := strings.Cut(line, " - ")
		fields, rest := strings.Fields(before), strings.Fields(after)
		if !found || len(fields) < 5 || len(rest) < 1 {
			return nil, fmt.Errorf("unrecognised mountinfo line: %q", line)
		}
		mounts = append(mounts, mount{Point: unescapeMountPath(fields[4]), FSType: rest[0]})
	}
	return mounts, sc.Err()
}

// unescapeMountPath turns the kernel's octal escapes (such as \040 for a
// space) back into the characters they stand for.
func unescapeMountPath(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isWithin reports whether path is dir or somewhere below it.
func isWithin(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// mountOf returns the most specific mount holding path. The zero mount, with
// no filesystem type, means no mount holds it.
func mountOf(path string, mounts []mount) mount {
	best := mount{}
	for _, m := range mounts {
		if isWithin(path, m.Point) && len(m.Point) >= len(best.Point) {
			best = m
		}
	}
	return best
}

// fileBudget keeps the walk out of a filesystem that holds more files than
// the agent can afford. syft keeps a record of every file it walks in
// memory, so a backup or storage area with millions of files would otherwise
// use up the memory limit and leave no inventory at all.
type fileBudget struct {
	// Limit is the most files a filesystem may hold and still be walked.
	// Zero means no limit.
	Limit uint64
	// Count reports how many files a filesystem holds, given its mount
	// point, without walking it. known is false when the filesystem does
	// not say.
	Count func(mountPoint string) (files uint64, known bool)
}

// kbPerFileWalked is roughly what each walked file costs in memory: 3 to 4 KB
// measured over four runs on two machines in November 2026.
const kbPerFileWalked = 4

// budgetFor works out how many files one filesystem may hold, from the
// agent's memory limit in MB. No memory limit means no file limit.
func budgetFor(maxMemoryMB int64) uint64 {
	if maxMemoryMB <= 0 {
		return 0
	}
	return uint64(maxMemoryMB) * 1024 / kbPerFileWalked
}

// filesOnFilesystem asks the kernel how many files a mounted filesystem
// holds. It is one call and reads nothing from the disk's directories.
func filesOnFilesystem(mountPoint string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(mountPoint, &st); err != nil || st.Files == 0 {
		return 0, false // btrfs, for one, does not count its files
	}
	return uint64(st.Files) - uint64(st.Ffree), true
}

// planScope works out how to walk only the given paths under root, staying
// off anything that is not a local filesystem and anything too big for the
// file budget.
func planScope(root string, paths []string, mounts []mount, budget fileBudget) (scope, error) {
	var sc scope

	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return sc, fmt.Errorf("resolve scan root: %w", err)
	}

	// refusal says why a mount must not be walked, or "" if it may be. The
	// filesystem holding root itself is never refused for its size: its
	// count covers the whole machine, not any one path on it.
	refusal := func(m mount) string {
		if !localFSTypes[m.FSType] {
			return skipReason(m.FSType)
		}
		if budget.Limit == 0 || budget.Count == nil || m.Point == root {
			return ""
		}
		if files, known := budget.Count(m.Point); known && files > budget.Limit {
			return fmt.Sprintf("about %d files on this filesystem, more than the limit of %d", files, budget.Limit)
		}
		return ""
	}
	skip := func(path, reason string) {
		if !slices.ContainsFunc(sc.Skipped, func(s skipped) bool { return s.Path == path }) {
			sc.Skipped = append(sc.Skipped, skipped{path, reason})
		}
	}

	for _, p := range paths {
		resolved, err := filepath.EvalSymlinks(p)
		if errors.Is(err, fs.ErrNotExist) {
			skip(p, "not present")
			continue
		}
		if err != nil {
			return sc, fmt.Errorf("resolve %s: %w", p, err)
		}
		if slices.Contains(sc.Walk, resolved) {
			continue
		}
		if reason := refusal(mountOf(resolved, mounts)); reason != "" {
			skip(resolved, reason)
			continue
		}
		sc.Walk = append(sc.Walk, resolved)
	}
	// a path inside another walked path is already covered
	resolved := sc.Walk
	sc.Walk = nil
	for _, p := range resolved {
		if !slices.ContainsFunc(resolved, func(w string) bool { return w != p && isWithin(p, w) }) {
			sc.Walk = append(sc.Walk, p)
		}
	}

	// A mount inside a walked path that must not be walked is cut out. Only
	// those mounts are asked about, so no question is put to a filesystem
	// the scan would never reach.
	var excluded []string
	for _, m := range mounts {
		inside := slices.ContainsFunc(sc.Walk, func(w string) bool { return m.Point != w && isWithin(m.Point, w) })
		if !inside || slices.Contains(excluded, m.Point) {
			continue
		}
		if reason := refusal(m); reason != "" {
			skip(m.Point, reason)
			excluded = append(excluded, m.Point)
		}
	}

	siblings, err := siblingsOf(root, sc.Walk)
	if err != nil {
		return sc, err
	}
	excluded = append(excluded, siblings...)

	for _, p := range excluded {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return sc, err
		}
		// Two patterns each. The first stops the walk at the path itself.
		// The second covers everything below it, because syft also jumps
		// straight to the target of any symlink it meets, and a link in a
		// walked path can point deep inside an excluded one.
		pattern := "./" + escapeGlob(filepath.ToSlash(rel))
		sc.Excludes = append(sc.Excludes, pattern, pattern+"/**")
	}
	return sc, nil
}

func skipReason(fsType string) string {
	if fsType == "" {
		return "filesystem type unknown"
	}
	return "filesystem type " + fsType
}

// siblingsOf lists everything under dir that is neither a walked path nor on
// the way to one. Only directories that lead to a walked path are read.
func siblingsOf(dir string, walk []string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		switch {
		case slices.Contains(walk, p):
			// walked in full
		case slices.ContainsFunc(walk, func(w string) bool { return isWithin(w, p) }):
			deeper, err := siblingsOf(p, walk)
			if err != nil {
				return nil, err
			}
			out = append(out, deeper...)
		default:
			out = append(out, p)
		}
	}
	return out, nil
}

// escapeGlob makes a literal path safe to use as a doublestar pattern.
func escapeGlob(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`*?[]{}\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
