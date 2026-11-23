package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// makeTree creates the given paths under a fresh temp dir. A trailing slash
// makes a directory, anything else an empty file. It returns the temp dir
// with symlinks resolved (macOS keeps temp dirs behind a /var symlink).
func makeTree(t *testing.T, paths ...string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	for _, p := range paths {
		full := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", p, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", p, err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return root
}

func under(root string, paths ...string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Join(root, p)
	}
	return out
}

func skippedPaths(sc scope) []string {
	var out []string
	for _, s := range sc.Skipped {
		out = append(out, s.Path)
	}
	return out
}

func assertHas(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("%s: missing %q in %q", what, w, got)
		}
	}
}

func assertLacks(t *testing.T, what string, got []string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		if slices.Contains(got, u) {
			t.Errorf("%s: should not contain %q, got %q", what, u, got)
		}
	}
}

func TestParseMountinfo(t *testing.T) {
	const sample = `22 28 0:21 / /proc rw,nosuid shared:14 - proc proc rw
28 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,discard
95 28 0:44 / /home rw,relatime shared:50 - autofs /etc/auto.home rw,fd=6,indirect
120 28 0:52 / /software ro,relatime shared:70 - nfs4 fileserver:/software ro,vers=4.2
130 28 8:17 / /mnt/my\040disk rw shared:80 master:2 - xfs /dev/sdb1 rw
`
	got, err := parseMountinfo(strings.NewReader(sample))
	if err != nil {
		t.Fatalf("parseMountinfo: %v", err)
	}
	want := []mount{
		{"/proc", "proc"},
		{"/", "ext4"},
		{"/home", "autofs"},
		{"/software", "nfs4"},
		{"/mnt/my disk", "xfs"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := parseMountinfo(strings.NewReader("not a mountinfo line\n")); err == nil {
		t.Error("a malformed line should be an error, not silently ignored")
	}
}

func TestPlanScope(t *testing.T) {
	t.Run("walks only the given paths and excludes their siblings", func(t *testing.T) {
		root := makeTree(t,
			"etc/os-release", "etc/passwd",
			"opt/app/bin/tool",
			"home/someone/",
			"var/lib/dpkg/status", "var/lib/other/", "var/log/",
		)
		paths := under(root, "etc/os-release", "opt", "var/lib/dpkg", "export")
		sc, err := planScope(root, paths, []mount{{root, "ext4"}}, fileBudget{})
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}

		if want := under(root, "etc/os-release", "opt", "var/lib/dpkg"); !slices.Equal(sc.Walk, want) {
			t.Errorf("Walk = %q, want %q", sc.Walk, want)
		}
		assertHas(t, "excludes", sc.Excludes, "./home", "./etc/passwd", "./var/lib/other", "./var/log")
		// everything below an excluded path is excluded too, so that a
		// symlink pointing into it is not followed
		assertHas(t, "excludes", sc.Excludes, "./home/**", "./var/lib/other/**", "./var/log/**")
		assertLacks(t, "excludes", sc.Excludes, "./etc", "./opt", "./var", "./var/lib", "./var/lib/dpkg", "./opt/app")
		assertHas(t, "skipped", skippedPaths(sc), filepath.Join(root, "export"))
	})

	t.Run("a network mount inside a walked path is excluded and reported", func(t *testing.T) {
		root := makeTree(t, "opt/local-app/", "opt/shared/", "opt/sharedness/")
		mounts := []mount{{root, "ext4"}, {filepath.Join(root, "opt/shared"), "nfs4"}}
		sc, err := planScope(root, under(root, "opt"), mounts, fileBudget{})
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		assertHas(t, "excludes", sc.Excludes, "./opt/shared", "./opt/shared/**")
		assertLacks(t, "excludes", sc.Excludes, "./opt/sharedness", "./opt/local-app")
		assertHas(t, "skipped", skippedPaths(sc), filepath.Join(root, "opt/shared"))
		for _, s := range sc.Skipped {
			if s.Path == filepath.Join(root, "opt/shared") && !strings.Contains(s.Reason, "nfs4") {
				t.Errorf("reason should name the filesystem type, got %q", s.Reason)
			}
		}
	})

	t.Run("a path that is itself on a network or autofs mount is not walked", func(t *testing.T) {
		root := makeTree(t, "export/", "srv/", "opt/")
		mounts := []mount{
			{root, "xfs"},
			{filepath.Join(root, "export"), "nfs"},
			{filepath.Join(root, "srv"), "autofs"},
		}
		sc, err := planScope(root, under(root, "export", "srv", "opt"), mounts, fileBudget{})
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if want := under(root, "opt"); !slices.Equal(sc.Walk, want) {
			t.Errorf("Walk = %q, want %q", sc.Walk, want)
		}
		assertHas(t, "excludes", sc.Excludes, "./export", "./srv")
		assertHas(t, "skipped", skippedPaths(sc), under(root, "export", "srv")...)
	})

	t.Run("a local mount inside a walked path is still walked", func(t *testing.T) {
		root := makeTree(t, "opt/bigdisk/")
		mounts := []mount{{root, "ext4"}, {filepath.Join(root, "opt/bigdisk"), "xfs"}}
		sc, err := planScope(root, under(root, "opt"), mounts, fileBudget{})
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		assertLacks(t, "excludes", sc.Excludes, "./opt/bigdisk")
		if len(sc.Skipped) != 0 {
			t.Errorf("nothing should be skipped, got %v", sc.Skipped)
		}
	})

	t.Run("a symlinked path is walked where it really lives", func(t *testing.T) {
		root := makeTree(t, "data/opt/app/", "data/other/")
		if err := os.Symlink(filepath.Join(root, "data/opt"), filepath.Join(root, "opt")); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		sc, err := planScope(root, under(root, "opt"), []mount{{root, "ext4"}}, fileBudget{})
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if want := under(root, "data/opt"); !slices.Equal(sc.Walk, want) {
			t.Errorf("Walk = %q, want %q", sc.Walk, want)
		}
		assertHas(t, "excludes", sc.Excludes, "./opt", "./data/other")
		assertLacks(t, "excludes", sc.Excludes, "./data", "./data/opt")
	})

	t.Run("a path inside another walked path is listed once, under its parent", func(t *testing.T) {
		root := makeTree(t, "usr/bin/", "usr/lib/os-release", "usr/local/", "etc/")
		for _, link := range []string{"bin", "etc/os-release"} {
			target := map[string]string{"bin": "usr/bin", "etc/os-release": "usr/lib/os-release"}[link]
			if err := os.Symlink(filepath.Join(root, target), filepath.Join(root, link)); err != nil {
				t.Fatalf("symlink: %v", err)
			}
		}
		paths := under(root, "etc/os-release", "bin", "usr/local", "usr")
		sc, err := planScope(root, paths, []mount{{root, "ext4"}}, fileBudget{})
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if want := under(root, "usr"); !slices.Equal(sc.Walk, want) {
			t.Errorf("Walk = %q, want %q", sc.Walk, want)
		}
		assertHas(t, "excludes", sc.Excludes, "./bin", "./etc")
		assertLacks(t, "excludes", sc.Excludes, "./usr", "./usr/bin", "./usr/local")
	})

	t.Run("glob characters in names are escaped", func(t *testing.T) {
		root := makeTree(t, "opt/", "we[ird]*name/")
		sc, err := planScope(root, under(root, "opt"), []mount{{root, "ext4"}}, fileBudget{})
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		assertHas(t, "excludes", sc.Excludes, `./we\[ird\]\*name`, `./we\[ird\]\*name/**`)
	})

	t.Run("a path whose filesystem type cannot be found is not walked", func(t *testing.T) {
		root := makeTree(t, "opt/")
		sc, err := planScope(root, under(root, "opt"), nil, fileBudget{})
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if len(sc.Walk) != 0 {
			t.Errorf("Walk = %q, want nothing", sc.Walk)
		}
		assertHas(t, "skipped", skippedPaths(sc), filepath.Join(root, "opt"))
	})
}
