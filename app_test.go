package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestAppTarget(t *testing.T) {
	// One host filesystem, and a process that sees it as its own root.
	host := makeTree(t,
		"srv/shop/requirements.txt",
		"srv/shop/.venv/",
		"srv/tool/.git/config",
		"opt/svc/app.jar",
		"home/someone/package.json",
	)
	proc := fakeProc(t, map[string]string{"42/root->": host})
	onHost := func(p string) string { return filepath.Join(host, p) }

	cases := []struct {
		name       string
		ctx        processContext
		wantPath   string
		wantReason bool
	}{
		{
			name:     "a project folder with a marker is walked",
			ctx:      processContext{Project: &project{Dir: "/srv/shop", Manifest: "requirements.txt"}},
			wantPath: onHost("srv/shop"),
		},
		{
			name:     "a jar on the command line is walked, ahead of any project",
			ctx:      processContext{FileArg: "/opt/svc/app.jar", Project: &project{Dir: "/srv/shop", Manifest: "requirements.txt"}},
			wantPath: onHost("opt/svc/app.jar"),
		},
		{
			name: "a folder found only from a git checkout is not",
			ctx:  processContext{Project: &project{Dir: "/srv/tool", GitRemote: "https://example.com/owner/tool"}},
		},
		{
			name: "no project and no jar: nothing to walk",
			ctx:  processContext{Cwd: "/srv/shop", FileArg: "/srv/shop/run.py"},
		},
		{
			name:       "a home directory is named but not walked",
			ctx:        processContext{Project: &project{Dir: "/home/someone", Manifest: "package.json"}},
			wantPath:   onHost("home/someone"),
			wantReason: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path, reason := appTarget(proc, host, 42, c.ctx)
			if path != c.wantPath || (reason != "") != c.wantReason {
				t.Errorf("got %q, %q; want %q, a reason: %v", path, reason, c.wantPath, c.wantReason)
			}
		})
	}

	t.Run("the same path inside a container is not the host's", func(t *testing.T) {
		theirs := makeTree(t, "srv/shop/requirements.txt")
		proc := fakeProc(t, map[string]string{"43/root->": theirs})
		ctx := processContext{Project: &project{Dir: "/srv/shop", Manifest: "requirements.txt"}}
		path, reason := appTarget(proc, host, 43, ctx)
		if path != "" || reason == "" {
			t.Errorf("got %q, %q; want no path and a reason", path, reason)
		}
	})

	t.Run("a symlinked project folder is reported where syft will find it", func(t *testing.T) {
		host := makeTree(t, "data/apps/shop/requirements.txt")
		if err := os.Symlink(filepath.Join(host, "data/apps"), filepath.Join(host, "srv")); err != nil {
			t.Fatal(err)
		}
		proc := fakeProc(t, map[string]string{"44/root->": host})
		ctx := processContext{Project: &project{Dir: "/srv/shop", Manifest: "requirements.txt"}}
		path, reason := appTarget(proc, host, 44, ctx)
		if path != filepath.Join(host, "data/apps/shop") || reason != "" {
			t.Errorf("got %q, %q; want the resolved folder", path, reason)
		}
	})
}

func TestIsHomeLike(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/root": true, "/home": true, "/home/someone": true, "/home/someone/": true,
		"/home/someone/app": false, "/srv/app": false, "/var/www": false,
	} {
		if got := isHomeLike(p); got != want {
			t.Errorf("isHomeLike(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestNoteAppScope(t *testing.T) {
	sc := scope{
		Walk:    []string{"/usr", "/srv", "/mnt/disk2/app"},
		Skipped: []skipped{{"/srv/big", "about 9000000 files on this filesystem, more than the limit of 524288"}, {"/nfs/app", "filesystem type nfs4"}},
	}
	listeners := []listener{{Processes: []process{
		{PID: 1, AppPath: "/srv/shop"},
		{PID: 2, AppPath: "/mnt/disk2/app"},
		{PID: 3, AppPath: "/srv/big/app"},
		{PID: 4, AppPath: "/nfs/app"},
		{PID: 5, AppPath: "/home/someone", AppSkipped: "a home directory, or a folder holding them"},
		{PID: 6},
	}}}

	if got := appPathsToWalk(listeners); len(got) != 4 {
		t.Errorf("appPathsToWalk = %q, want the four not already refused", got)
	}

	noteAppScope(listeners, sc)
	want := map[int]string{
		1: "",
		2: "",
		3: "about 9000000 files on this filesystem, more than the limit of 524288",
		4: "filesystem type nfs4",
		5: "a home directory, or a folder holding them",
		6: "",
	}
	for _, p := range listeners[0].Processes {
		if p.AppSkipped != want[p.PID] {
			t.Errorf("PID %d: AppSkipped = %q, want %q", p.PID, p.AppSkipped, want[p.PID])
		}
	}
}

func TestCountFiles(t *testing.T) {
	dir := makeTree(t, "a", "b", "sub/c", "sub/deeper/d")
	outside := makeTree(t, "x", "y", "z")
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	// a, b, sub, sub/c, sub/deeper, sub/deeper/d, and the link itself (not followed)
	if files, over := countFiles(dir, 100); files != 7 || over {
		t.Errorf("countFiles = %d, %v; want 7, not over", files, over)
	}
	if files, over := countFiles(dir, 3); !over || files != 4 {
		t.Errorf("countFiles with limit 3 = %d, %v; want to stop at 4, over", files, over)
	}
	if files, over := countFiles(filepath.Join(dir, "gone"), 3); files != 0 || over {
		t.Errorf("a missing folder = %d, %v; want 0, not over", files, over)
	}
}

func TestLimitAppPaths(t *testing.T) {
	host := makeTree(t, "srv/inside/", "home/u/small/", "home/u/medium/", "home/u/big/", "opt2/app.jar", "net/app/")
	at := func(p string) string { return filepath.Join(host, p) }
	sizes := map[string]uint64{at("home/u/small"): 10, at("home/u/medium"): 60, at("home/u/big"): 5000, at("srv/inside"): 99999, at("net/app"): 99999}
	var counted []string
	count := func(dir string, limit uint64) (uint64, bool) {
		counted = append(counted, dir)
		if sizes[dir] > limit {
			return limit + 1, true
		}
		return sizes[dir], false
	}
	mounts := []mount{{"/", "ext4"}, {at("net"), "nfs4"}}
	listeners := []listener{
		{Processes: []process{{PID: 1, AppPath: at("home/u/small")}, {PID: 2, AppPath: at("srv/inside")}}},
		{Processes: []process{{PID: 3, AppPath: at("home/u/big")}, {PID: 4, AppPath: at("home/u/medium")}}},
		{Processes: []process{{PID: 5, AppPath: at("opt2/app.jar")}, {PID: 6, AppPath: at("net/app")}}},
		{Processes: []process{{PID: 3, AppPath: at("home/u/big")}}}, // the same process on a second socket
	}

	limitAppPaths(listeners, []string{at("srv")}, mounts, 100, count)

	if slices.Contains(counted, at("srv/inside")) || slices.Contains(counted, at("net/app")) {
		t.Errorf("counted %q; a default path and a network filesystem must not be counted", counted)
	}
	skippedPIDs := map[int]bool{}
	for _, l := range listeners {
		for _, p := range l.Processes {
			if p.AppSkipped != "" {
				skippedPIDs[p.PID] = true
			}
		}
	}
	// small (10) and medium (60) and the jar (1) fit in 100; big does not.
	if want := map[int]bool{3: true}; !maps.Equal(skippedPIDs, want) {
		t.Errorf("skipped PIDs = %v, want %v", skippedPIDs, want)
	}
	if got := listeners[3].Processes[0].AppSkipped; got == "" {
		t.Error("every copy of a skipped process should carry the reason")
	}
}

func TestLimitAppPathsWalksTheSmallestFirst(t *testing.T) {
	host := makeTree(t, "a/", "b/", "c/")
	at := func(p string) string { return filepath.Join(host, p) }
	sizes := map[string]uint64{at("a"): 70, at("b"): 40, at("c"): 50}
	count := func(dir string, limit uint64) (uint64, bool) { return sizes[dir], sizes[dir] > limit }
	// The biggest is listed first; first come first served would walk only it.
	listeners := []listener{{Processes: []process{
		{PID: 1, AppPath: at("a")}, {PID: 2, AppPath: at("b")}, {PID: 3, AppPath: at("c")},
	}}}

	limitAppPaths(listeners, nil, []mount{{"/", "ext4"}}, 100, count)

	for _, p := range listeners[0].Processes {
		if skipped := p.AppSkipped != ""; skipped != (p.PID == 1) {
			t.Errorf("PID %d: AppSkipped = %q; want only the 70-file folder skipped", p.PID, p.AppSkipped)
		}
	}
}
