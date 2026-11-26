package main

import (
	"cmp"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// appFileAllowance is how many files all the app paths outside the default
// scan paths may hold between them and still be walked. syft keeps about
// 4 KB per walked file in memory, and going over the memory limit loses the
// whole inventory, so an app folder that would push past this is skipped
// and reported instead. The smallest folders are walked first. 100,000
// was agreed with the user on 2026-11-26 as a starting point, to be
// revisited after runs on real servers.
const appFileAllowance = 100_000

// A listening process's own code and its dependencies live in its app: the
// jar it runs, or its project folder. The agent adds that path to the walk
// so that syft catalogues what is in it, and records the path on the
// process so the central service can tell which artifacts belong to it.

// appTarget works out what to catalogue for one process. It returns the
// path as it is on the host, symlinks resolved, so that it is a prefix of
// the locations syft reports. A reason means the path is not to be walked;
// the path is still given when it is a host path.
//
// What is catalogued:
//   - a .jar or .war the process was started with, which holds every
//     dependency it runs with;
//   - otherwise its project folder, but only when a manifest or marker file
//     was found there. A folder found only from a git checkout could be
//     anything, a whole home directory kept in git, say.
func appTarget(procRoot, hostRoot string, pid int, ctx processContext) (appPath, reason string) {
	var want string
	switch {
	case isJavaArchive(ctx.FileArg):
		want = ctx.FileArg
	case ctx.Project != nil && ctx.Project.Manifest != "":
		want = ctx.Project.Dir
	default:
		return "", ""
	}

	// Only walk the host's path when it is the very file or folder the
	// process sees. Inside a container the same path is something else.
	// This is a stat through /proc/PID/root, not os.Root: os.Root refuses
	// any symlink with an absolute target, and a host link such as
	// /srv -> /data/srv is one. (The kernel resolves such a link inside a
	// container against the agent's root, so at worst a container path
	// that leads back to the very same host folder is walked. The walk
	// rules still apply to it.)
	theirs, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(pid), "root", want))
	if err != nil {
		return "", "cannot look at it as the process sees it"
	}
	onHost := filepath.Join(hostRoot, want)
	ours, err := os.Stat(onHost)
	if err != nil || !os.SameFile(theirs, ours) {
		return "", "not the host's own file or folder (inside a container, say)"
	}

	hostReal, err := filepath.EvalSymlinks(hostRoot)
	if err != nil {
		return "", "cannot resolve the host's root"
	}
	resolved, err := filepath.EvalSymlinks(onHost)
	if err != nil {
		return "", "cannot resolve the path"
	}
	rel, err := filepath.Rel(hostReal, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", "resolves outside the host's root"
	}
	if isHomeLike(want) || isHomeLike("/"+filepath.ToSlash(rel)) {
		return resolved, "a home directory, or a folder holding them"
	}
	return resolved, ""
}

func isJavaArchive(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war")
}

// isHomeLike reports whether p is a home directory, or holds them, by its
// name alone. Nothing is looked up, so homes elsewhere (such as
// /users/someone) are not caught.
func isHomeLike(p string) bool {
	p = path.Clean(p)
	return p == "/" || p == "/root" || p == "/home" || path.Dir(p) == "/home"
}

// limitAppPaths keeps the app paths outside the default scan paths within
// one shared allowance of files. Every such path is counted first, then the
// smallest are walked first: that checks as many apps as the allowance
// allows, and picks the same ones on every run. An app path that does not
// fit gets a reason in AppSkipped on every process using it. Paths inside a
// default scan path are not counted (the default walk covers them
// already), nor are paths on a filesystem the walk refuses, so that no
// network filesystem is ever read here.
func limitAppPaths(listeners []listener, defaults []string, mounts []mount, allowance uint64,
	count func(dir string, limit uint64) (files uint64, over bool)) {
	type app struct {
		path  string
		files uint64
		over  bool
	}
	var apps []app
	for _, l := range listeners {
		for _, p := range l.Processes {
			at := p.AppPath
			if at == "" || p.AppSkipped != "" || slices.ContainsFunc(apps, func(a app) bool { return a.path == at }) {
				continue
			}
			if slices.ContainsFunc(defaults, func(d string) bool { return isWithin(at, d) }) ||
				!localFSTypes[mountOf(at, mounts).FSType] {
				continue
			}
			a := app{path: at, files: 1} // a jar is one file
			if info, err := os.Lstat(at); err == nil && info.IsDir() {
				a.files, a.over = count(at, allowance)
			}
			apps = append(apps, a)
		}
	}
	slices.SortFunc(apps, func(a, b app) int {
		return cmp.Or(cmp.Compare(a.files, b.files), cmp.Compare(a.path, b.path))
	})

	left := allowance
	for _, a := range apps {
		switch {
		case a.over:
			skipApp(listeners, a.path, fmt.Sprintf("more than the %d files allowed for app folders", allowance))
		case a.files > left:
			skipApp(listeners, a.path, fmt.Sprintf(
				"%d files, more than the %d left of the %d allowed for app folders", a.files, left, allowance))
		default:
			left -= a.files
		}
	}
}

func skipApp(listeners []listener, appPath, reason string) {
	for i := range listeners {
		for j := range listeners[i].Processes {
			if p := &listeners[i].Processes[j]; p.AppPath == appPath {
				p.AppSkipped = reason
			}
		}
	}
}

// countFiles counts the entries (files and folders) under dir by reading
// directory entries only: no file is opened or looked at, only folders.
// It follows no symlink, stays on dir's own filesystem, and stops as soon
// as the count passes limit, so its cost is bounded by limit whatever the
// size of the tree.
func countFiles(dir string, limit uint64) (files uint64, over bool) {
	top, err := os.Lstat(dir)
	if err != nil {
		return 0, false // the scope plan reports it as not present
	}
	device := deviceOf(top)
	pending := []string{dir}
	for len(pending) > 0 {
		d := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		f, err := os.Open(d)
		if err != nil {
			continue
		}
		for {
			entries, err := f.ReadDir(1024) // in batches: one folder may hold millions
			for _, e := range entries {
				if files++; files > limit {
					f.Close()
					return files, true
				}
				if e.IsDir() { // a symlink is never a folder here
					sub := filepath.Join(d, e.Name())
					if info, err := os.Lstat(sub); err == nil && deviceOf(info) == device {
						pending = append(pending, sub)
					}
				}
			}
			if err != nil {
				break
			}
		}
		f.Close()
	}
	return files, false
}

func deviceOf(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}

// resolvedPaths resolves the symlinks in each path, leaving out those that
// do not exist.
func resolvedPaths(paths []string) []string {
	var out []string
	for _, p := range paths {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// appPathsToWalk lists, once each, the app paths that may be walked.
func appPathsToWalk(listeners []listener) []string {
	var paths []string
	for _, l := range listeners {
		for _, p := range l.Processes {
			if p.AppPath != "" && p.AppSkipped == "" && !slices.Contains(paths, p.AppPath) {
				paths = append(paths, p.AppPath)
			}
		}
	}
	return paths
}

// noteAppScope records on each process whose app path the scope does not
// walk why it was left out.
func noteAppScope(listeners []listener, sc scope) {
	for i := range listeners {
		for j := range listeners[i].Processes {
			p := &listeners[i].Processes[j]
			if p.AppPath != "" && p.AppSkipped == "" {
				p.AppSkipped = whyNotWalked(p.AppPath, sc)
			}
		}
	}
}

// whyNotWalked returns "" when sc walks path, or the reason it does not.
func whyNotWalked(path string, sc scope) string {
	for _, s := range sc.Skipped {
		if isWithin(path, s.Path) {
			return s.Reason
		}
	}
	if slices.ContainsFunc(sc.Walk, func(w string) bool { return isWithin(path, w) }) {
		return ""
	}
	return "not walked"
}
