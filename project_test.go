package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// processRoot builds a pretend filesystem as some process sees it. Keys are
// paths under it; a key ending in "->" makes a symlink to the value.
func processRoot(t *testing.T, entries map[string]string) string {
	t.Helper()
	return fakeProc(t, entries) // same shape: files and symlinks under a temp dir
}

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestUnitFromCgroup(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/nginx.service\n":                                          "nginx.service",
		"0::/system.slice/docker-9f30ab274cf0.scope\n":                              "docker-9f30ab274cf0.scope",
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/demo.service\n": "demo.service",
		"0::/\n":                   "",
		"":                         "",
		"12:pids:/old/v1/layout\n": "",
	}
	for cgroup, want := range cases {
		if got := unitFromCgroup(cgroup); got != want {
			t.Errorf("unitFromCgroup(%q) = %q, want %q", cgroup, got, want)
		}
	}
}

func TestParseManifest(t *testing.T) {
	cases := []struct {
		file, data, name, version string
		ok                        bool
	}{
		{"package.json", `{"name":"demo-app","version":"1.2.3","description":"never read"}`, "demo-app", "1.2.3", true},
		{"composer.json", `{"name":"acme/site"}`, "acme/site", "", true},
		{"pyproject.toml", "[project]\nname = \"analysis\"\nversion = \"0.4.0\"\n", "analysis", "0.4.0", true},
		{"pyproject.toml", "[tool.poetry]\nname = \"old-style\"\nversion = \"2.0\"\n", "old-style", "2.0", true},
		{"pyproject.toml", "[project]\nname = \"dyn\"\ndynamic = [\"version\"]\n", "dyn", "", true},
		{"Cargo.toml", "[package]\nname = \"tool\"\nversion = { workspace = true }\n", "tool", "", true},
		{"go.mod", "// comment\nmodule example.com/owner/thing\n\ngo 1.27\n", "example.com/owner/thing", "", true},
		{"package.json", `not json`, "", "", false},
		{"pyproject.toml", "[build-system]\nrequires = []\n", "", "", false},
		{"package.json", `{"version":"1.0.0"}`, "", "", false},
	}
	for _, c := range cases {
		name, version, ok := parseManifest(c.file, []byte(c.data))
		if name != c.name || version != c.version || ok != c.ok {
			t.Errorf("parseManifest(%s, %q) = %q, %q, %v; want %q, %q, %v",
				c.file, c.data, name, version, ok, c.name, c.version, c.ok)
		}
	}
}

func TestGitRemote(t *testing.T) {
	cases := map[string]string{
		"[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.com/owner/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n": "https://example.com/owner/repo.git",
		// credentials in the URL never leave the machine
		"[remote \"origin\"]\n\turl = https://someone:s3cret-token@example.com/owner/repo.git\n": "https://example.com/owner/repo.git",
		"[remote \"origin\"]\n\turl = git@example.com:owner/repo.git\n":                          "example.com:owner/repo.git",
		// origin wins over an earlier remote; with no origin the first is used
		"[remote \"upstream\"]\n\turl = https://example.com/up/repo\n[remote \"origin\"]\n\turl = https://example.com/me/repo\n": "https://example.com/me/repo",
		"[remote \"upstream\"]\n\turl = https://example.com/up/repo\n":                                                           "https://example.com/up/repo",
		// a url outside a remote section is not a remote
		"[submodule \"x\"]\n\turl = https://example.com/sub\n": "",
		"[core]\n\tbare = false\n":                             "",
	}
	for config, want := range cases {
		if got := gitRemote([]byte(config)); got != want {
			t.Errorf("gitRemote(%q) = %q, want %q", config, got, want)
		}
	}
}

const (
	hashA = "1111111111111111111111111111111111111111"
	hashB = "2222222222222222222222222222222222222222"
)

func TestFindProject(t *testing.T) {
	t.Run("manifest below, git checkout above", func(t *testing.T) {
		root := openRoot(t, processRoot(t, map[string]string{
			"srv/repo/.git/config":          "[remote \"origin\"]\n\turl = https://example.com/owner/repo.git\n",
			"srv/repo/.git/HEAD":            "ref: refs/heads/main\n",
			"srv/repo/.git/refs/heads/main": hashA + "\n",
			"srv/repo/app/pyproject.toml":   "[project]\nname = \"analysis\"\nversion = \"0.4.0\"\n",
			"srv/repo/app/src/main.py":      "",
		}))
		got := findProject(root, "/srv/repo/app/src")
		want := project{
			Dir: "/srv/repo/app", Manifest: "pyproject.toml", Name: "analysis", Version: "0.4.0",
			GitRemote: "https://example.com/owner/repo.git", GitCommit: hashA,
		}
		if got == nil || *got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("git checkout with no manifest, commit in packed-refs", func(t *testing.T) {
		root := openRoot(t, processRoot(t, map[string]string{
			"opt/tool/.git/config":      "[remote \"origin\"]\n\turl = https://example.com/owner/tool\n",
			"opt/tool/.git/HEAD":        "ref: refs/heads/main\n",
			"opt/tool/.git/packed-refs": "# pack-refs with: peeled fully-peeled sorted\n" + hashB + " refs/heads/main\n",
		}))
		got := findProject(root, "/opt/tool")
		want := project{Dir: "/opt/tool", GitRemote: "https://example.com/owner/tool", GitCommit: hashB}
		if got == nil || *got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a marker file marks the folder, with no name", func(t *testing.T) {
		root := openRoot(t, processRoot(t, map[string]string{
			"srv/flask/requirements.txt": "flask==3.0.0\n",
			"srv/flask/app/server.py":    "",
		}))
		got := findProject(root, "/srv/flask/app")
		want := project{Dir: "/srv/flask", Manifest: "requirements.txt"}
		if got == nil || *got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a manifest with a name wins over a marker in the same folder", func(t *testing.T) {
		root := openRoot(t, processRoot(t, map[string]string{
			"srv/api/pom.xml":      "<project/>",
			"srv/api/package.json": `{"name":"api-docs","version":"1.0.0"}`,
		}))
		got := findProject(root, "/srv/api")
		if got == nil || got.Manifest != "package.json" || got.Name != "api-docs" {
			t.Errorf("got %+v, want the package.json", got)
		}
	})

	t.Run("a symlink or folder at a marker's name is not a marker", func(t *testing.T) {
		root := openRoot(t, processRoot(t, map[string]string{
			"srv/a/real.txt":           "",
			"srv/a/requirements.txt->": "real.txt",
			"srv/b/Gemfile/inside":     "",
		}))
		for _, dir := range []string{"/srv/a", "/srv/b"} {
			if got := findProject(root, dir); got != nil {
				t.Errorf("%s: got %+v, want nothing", dir, got)
			}
		}
	})

	t.Run("detached HEAD", func(t *testing.T) {
		root := openRoot(t, processRoot(t, map[string]string{
			"opt/tool/.git/config": "[core]\n",
			"opt/tool/.git/HEAD":   hashA + "\n",
		}))
		if got := findProject(root, "/opt/tool"); got == nil || got.GitCommit != hashA {
			t.Errorf("got %+v, want commit %s", got, hashA)
		}
	})

	t.Run("nothing found, and the search stops after a few levels", func(t *testing.T) {
		root := openRoot(t, processRoot(t, map[string]string{
			"package.json":          `{"name":"at-the-root"}`,
			"a/package.json":        `{"name":"too-far-up"}`,
			"a/b/c/d/e/f/g/main.py": "",
		}))
		if got := findProject(root, "/a/b/c/d/e/f/g"); got != nil {
			t.Errorf("got %+v, want nothing", got)
		}
		if got := findProject(root, "/"); got != nil {
			t.Errorf("the filesystem root is never a project, got %+v", got)
		}
	})

	t.Run("a symlink planted where a manifest should be is not read", func(t *testing.T) {
		secret := filepath.Join(t.TempDir(), "secret.json")
		if err := os.WriteFile(secret, []byte(`{"name":"leaked-from-elsewhere"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		root := openRoot(t, processRoot(t, map[string]string{
			"home/someone/proj/package.json->":  secret,
			"home/someone/proj2/real.json":      `{"name":"inside-the-root"}`,
			"home/someone/proj2/package.json->": "real.json",
		}))
		for _, dir := range []string{"/home/someone/proj", "/home/someone/proj2"} {
			if got := findProject(root, dir); got != nil {
				t.Errorf("%s: a symlinked manifest was read: %+v", dir, got)
			}
		}
	})

	t.Run("a directory symlink cannot lead out of the process's filesystem", func(t *testing.T) {
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "package.json"), []byte(`{"name":"outside"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		root := openRoot(t, processRoot(t, map[string]string{
			"app->": outside,
		}))
		if got := findProject(root, "/app"); got != nil {
			t.Errorf("read a manifest outside the root: %+v", got)
		}
	})
}

func TestDescribeContext(t *testing.T) {
	theirRoot := processRoot(t, map[string]string{
		"srv/bot/package.json": `{"name":"demo-bot","version":"3.1.0"}`,
		"srv/bot/src/index.js": "",
		"etc/secret.conf":      "",
	})
	proc := fakeProc(t, map[string]string{
		"42/cgroup":  "0::/system.slice/demo-bot.service\n",
		"42/cwd->":   "/",
		"42/root->":  theirRoot,
		"42/cmdline": strings.Join([]string{"/usr/bin/node", "--token=hunter2", "/srv/bot/src/index.js", "/etc/secret.conf"}, "\x00") + "\x00",
	})

	got := describeContext(proc, 42)

	if got.Unit != "demo-bot.service" {
		t.Errorf("Unit = %q", got.Unit)
	}
	if got.Cwd != "/" {
		t.Errorf("Cwd = %q", got.Cwd)
	}
	if got.FileArg != "/srv/bot/src/index.js" {
		t.Errorf("FileArg = %q, want the first argument that is a file", got.FileArg)
	}
	want := project{Dir: "/srv/bot", Manifest: "package.json", Name: "demo-bot", Version: "3.1.0"}
	if got.Project == nil || *got.Project != want {
		t.Errorf("Project = %+v, want %+v", got.Project, want)
	}

	t.Run("a relative script is found from the working directory", func(t *testing.T) {
		proc := fakeProc(t, map[string]string{
			"43/cwd->":   "/srv/bot",
			"43/root->":  theirRoot,
			"43/cmdline": "node\x00src/index.js\x00",
		})
		if got := describeContext(proc, 43); got.FileArg != "/srv/bot/src/index.js" || got.Project == nil {
			t.Errorf("got %+v", got)
		}
	})

	t.Run("a process that has gone gives an empty answer, not a failure", func(t *testing.T) {
		if got := describeContext(proc, 999); got.Project != nil || got.Unit != "" {
			t.Errorf("got %+v", got)
		}
	})
}
