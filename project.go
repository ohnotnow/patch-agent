package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
)

// project says what a listening process's code calls itself: the name and
// version from its manifest, and where its git checkout came from. Nothing
// free-text is collected (no README, no description), because a researcher's
// own words can name people or restricted work.
type project struct {
	Dir       string `json:"dir"`                // as the process sees it
	Manifest  string `json:"manifest,omitempty"` // a manifest or a marker file; a marker gives no name or version
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	GitRemote string `json:"gitRemote,omitempty"`
	GitCommit string `json:"gitCommit,omitempty"`
}

// processContext is what /proc says about how a process was started.
type processContext struct {
	Unit    string   // systemd unit or container scope, from its cgroup
	Cwd     string   // working directory, as the process sees it
	FileArg string   // the first argument that is a file, as the process sees it
	Project *project // nil when no manifest or git checkout was found
}

const (
	// How far above the file argument or working directory to look for a project.
	projectSearchLevels = 5
	// The most that is read of any one file.
	projectFileLimit = 256 << 10
)

var manifestNames = []string{"pyproject.toml", "package.json", "composer.json", "go.mod", "Cargo.toml"}

// markerNames mark an app's folder but carry no name worth reading. They
// are only looked at, never read. A folder with a manifest or a marker is
// walked so that syft catalogues what is in it (installed packages and
// lockfiles); syft need not read the marker itself. Only ecosystems syft
// can catalogue belong here.
var markerNames = []string{
	"requirements.txt",         // Python
	"Gemfile",                  // Ruby
	"renv.lock", "DESCRIPTION", // R
	"stack.yaml", "cabal.project", // Haskell
	"pom.xml", "build.gradle", "build.gradle.kts", // Java
}

// describeContext reads a process's unit, working directory and first file
// argument from /proc, then makes a few small reads of fixed file names near
// that file and the working directory to identify the project. It lists no directories and follows no links out of
// the process's own filesystem view.
func describeContext(procRoot string, pid int) processContext {
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	var ctx processContext

	if cgroup, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		ctx.Unit = unitFromCgroup(string(cgroup))
	}
	ctx.Cwd, _ = os.Readlink(filepath.Join(dir, "cwd"))

	// Everything else is read through the process's own root, so that paths
	// mean what they mean to the process (inside a container, say), and a
	// symlink cannot lead outside it.
	root, err := os.OpenRoot(filepath.Join(dir, "root"))
	if err != nil {
		return ctx
	}
	defer root.Close()

	if cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		ctx.FileArg = fileArgument(root, ctx.Cwd, strings.Split(string(cmdline), "\x00"))
	}

	starts := []string{}
	if ctx.FileArg != "" {
		starts = append(starts, path.Dir(ctx.FileArg))
	}
	starts = append(starts, ctx.Cwd)
	for _, start := range starts {
		if p := findProject(root, start); p != nil {
			ctx.Project = p
			break
		}
	}
	return ctx
}

// unitFromCgroup returns the last element of the process's cgroup path, such
// as "nginx.service" or "docker-<id>.scope".
func unitFromCgroup(cgroup string) string {
	for _, line := range strings.Split(strings.TrimSpace(cgroup), "\n") {
		// "0::/system.slice/nginx.service" on cgroup v2
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			if unit := path.Base(rest); unit != "/" && unit != "." {
				return unit
			}
		}
	}
	return ""
}

// fileArgument picks the first argument after the program itself that
// names an existing regular file. Only that path is kept; the rest of the
// command line can hold secrets and is never reported.
func fileArgument(root *os.Root, cwd string, args []string) string {
	if len(args) < 2 {
		return ""
	}
	for _, arg := range args[1:] {
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		candidate := arg
		if !path.IsAbs(candidate) {
			if cwd == "" {
				continue
			}
			candidate = path.Join(cwd, candidate)
		}
		candidate = path.Clean(candidate)
		if info, err := root.Stat(inRoot(candidate)); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

// inRoot turns an absolute path into one relative to an os.Root.
func inRoot(p string) string {
	if rel := strings.TrimPrefix(path.Clean(p), "/"); rel != "" {
		return rel
	}
	return "."
}

// findProject looks in dir and a few levels above it for a manifest and a
// git checkout. It stops at the git checkout's top, and never looks in "/".
func findProject(root *os.Root, dir string) *project {
	if !path.IsAbs(dir) {
		return nil
	}
	var p project
	found := false
	dir = path.Clean(dir)
	for level := 0; level < projectSearchLevels && dir != "/"; level, dir = level+1, path.Dir(dir) {
		if p.Manifest == "" {
			for _, name := range manifestNames {
				data, ok := readSmallFile(root, path.Join(dir, name))
				if !ok {
					continue
				}
				if projectName, version, ok := parseManifest(name, data); ok {
					p.Dir, p.Manifest, p.Name, p.Version = dir, name, projectName, version
					found = true
					break
				}
			}
		}
		if p.Manifest == "" {
			for _, name := range markerNames {
				if isRegularFile(root, path.Join(dir, name)) {
					p.Dir, p.Manifest = dir, name
					found = true
					break
				}
			}
		}
		if config, ok := readSmallFile(root, path.Join(dir, ".git/config")); ok {
			if !found {
				p.Dir = dir
			}
			p.GitRemote = gitRemote(config)
			p.GitCommit = gitCommit(root, path.Join(dir, ".git"))
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	return &p
}

// isRegularFile reports whether name is a regular file, not following a
// symlink at that name.
func isRegularFile(root *os.Root, name string) bool {
	info, err := root.Lstat(inRoot(name))
	return err == nil && info.Mode().IsRegular()
}

// readSmallFile reads up to projectFileLimit bytes of a regular file. It
// refuses a symlink, a pipe or a device at that name: any user can leave one
// there, and the agent runs as root.
func readSmallFile(root *os.Root, name string) ([]byte, bool) {
	// Look without following, then open, then check the opened file is the
	// one that was looked at. os.Root follows a symlink that stays inside
	// the root even when asked not to, so the open alone proves nothing.
	seen, err := root.Lstat(inRoot(name))
	if err != nil || !seen.Mode().IsRegular() {
		return nil, false
	}
	f, err := root.OpenFile(inRoot(name), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !os.SameFile(seen, opened) {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, projectFileLimit))
	if err != nil {
		return nil, false
	}
	return data, true
}

// parseManifest pulls the name and version out of a project manifest. A file
// that does not parse, or has no name, is treated as not a manifest. Parse
// errors are never reported, since they can quote the file.
func parseManifest(fileName string, data []byte) (name, version string, ok bool) {
	switch fileName {
	case "package.json", "composer.json":
		var doc struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &doc) != nil {
			return "", "", false
		}
		name, version = doc.Name, doc.Version
	case "pyproject.toml", "Cargo.toml":
		var doc map[string]any
		if toml.Unmarshal(data, &doc) != nil {
			return "", "", false
		}
		for _, table := range [][]string{{"project"}, {"tool", "poetry"}, {"package"}} {
			if name = tomlString(doc, append(table, "name")...); name != "" {
				version = tomlString(doc, append(table, "version")...)
				break
			}
		}
	case "go.mod":
		for _, line := range strings.Split(string(data), "\n") {
			if module, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
				name = strings.Trim(strings.TrimSpace(module), `"`)
				break
			}
		}
	}
	if name == "" {
		return "", "", false
	}
	return name, version, true
}

func tomlString(doc map[string]any, keys ...string) string {
	var current any = doc
	for _, key := range keys {
		table, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = table[key]
	}
	s, _ := current.(string)
	return s
}

var gitRemoteSection = regexp.MustCompile(`^\[remote\s+"([^"]+)"\]$`)

// gitRemote returns the URL of the "origin" remote in a .git/config, or of
// the first remote when there is no origin, with any credentials removed.
func gitRemote(config []byte) string {
	var first, origin, section string
	for _, line := range strings.Split(string(config), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = ""
			if m := gitRemoteSection.FindStringSubmatch(line); m != nil {
				section = m[1]
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if section == "" || !found || strings.TrimSpace(key) != "url" {
			continue
		}
		remote := cleanRemote(strings.TrimSpace(value))
		if first == "" {
			first = remote
		}
		if section == "origin" && origin == "" {
			origin = remote
		}
	}
	if origin != "" {
		return origin
	}
	return first
}

// cleanRemote strips a user name, password or token from a remote URL. A URL
// it cannot parse is dropped, not passed on.
func cleanRemote(remote string) string {
	if !strings.Contains(remote, "://") {
		// "git@host:owner/repo.git" form: the part before "@" is a login
		// name, but drop it anyway so nothing personal travels.
		if _, hostAndPath, found := strings.Cut(remote, "@"); found {
			return hostAndPath
		}
		return remote
	}
	u, err := url.Parse(remote)
	if err != nil {
		return ""
	}
	u.User, u.RawQuery, u.Fragment = nil, "", ""
	return u.String()
}

var gitHash = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// gitCommit returns the commit a checkout is at, or "" if it cannot tell.
func gitCommit(root *os.Root, gitDir string) string {
	head, ok := readSmallFile(root, path.Join(gitDir, "HEAD"))
	if !ok {
		return ""
	}
	ref, isRef := strings.CutPrefix(strings.TrimSpace(string(head)), "ref: ")
	if !isRef {
		return validHash(ref)
	}
	if !strings.HasPrefix(ref, "refs/") || strings.Contains(ref, "..") {
		return ""
	}
	if loose, ok := readSmallFile(root, path.Join(gitDir, ref)); ok {
		return validHash(string(loose))
	}
	packed, ok := readSmallFile(root, path.Join(gitDir, "packed-refs"))
	if !ok {
		return ""
	}
	for _, line := range bytes.Split(packed, []byte("\n")) {
		if hash, name, found := strings.Cut(string(line), " "); found && name == ref {
			return validHash(hash)
		}
	}
	return ""
}

func validHash(s string) string {
	if s = strings.TrimSpace(s); gitHash.MatchString(s) {
		return s
	}
	return ""
}
