package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// countsOf makes a fileBudget.Count from a table of mount point to file
// count. A mount missing from the table does not say how many files it has.
func countsOf(t *testing.T, counts map[string]uint64) func(string) (uint64, bool) {
	t.Helper()
	return func(mountPoint string) (uint64, bool) {
		files, known := counts[mountPoint]
		return files, known
	}
}

func skipReasonFor(sc scope, path string) string {
	for _, s := range sc.Skipped {
		if s.Path == path {
			return s.Reason
		}
	}
	return ""
}

func TestPlanScopeFileBudget(t *testing.T) {
	t.Run("a wanted path on a filesystem with too many files is skipped and says why", func(t *testing.T) {
		root := makeTree(t, "export/backups/", "opt/")
		export := filepath.Join(root, "export")
		mounts := []mount{{root, "ext4"}, {export, "xfs"}}
		budget := fileBudget{Limit: 500_000, Count: countsOf(t, map[string]uint64{export: 50_000_000, root: 200_000})}

		sc, err := planScope(root, under(root, "export", "opt"), mounts, budget)
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if want := under(root, "opt"); !slices.Equal(sc.Walk, want) {
			t.Errorf("Walk = %q, want %q", sc.Walk, want)
		}
		assertHas(t, "excludes", sc.Excludes, "./export", "./export/**")
		reason := skipReasonFor(sc, export)
		if !strings.Contains(reason, "50000000") || !strings.Contains(reason, "500000") {
			t.Errorf("reason should give the count and the limit, got %q", reason)
		}
	})

	t.Run("a huge filesystem mounted inside a walked path is cut out", func(t *testing.T) {
		root := makeTree(t, "opt/app/", "opt/archive/")
		archive := filepath.Join(root, "opt/archive")
		mounts := []mount{{root, "ext4"}, {archive, "ext4"}}
		budget := fileBudget{Limit: 1000, Count: countsOf(t, map[string]uint64{archive: 9999})}

		sc, err := planScope(root, under(root, "opt"), mounts, budget)
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if want := under(root, "opt"); !slices.Equal(sc.Walk, want) {
			t.Errorf("Walk = %q, want %q", sc.Walk, want)
		}
		assertHas(t, "excludes", sc.Excludes, "./opt/archive", "./opt/archive/**")
		assertLacks(t, "excludes", sc.Excludes, "./opt/app")
		if skipReasonFor(sc, archive) == "" {
			t.Errorf("the cut-out filesystem should be reported, got %+v", sc.Skipped)
		}
	})

	t.Run("a filesystem under the limit is walked", func(t *testing.T) {
		root := makeTree(t, "srv/")
		srv := filepath.Join(root, "srv")
		budget := fileBudget{Limit: 1000, Count: countsOf(t, map[string]uint64{srv: 1000})}
		sc, err := planScope(root, under(root, "srv"), []mount{{root, "ext4"}, {srv, "ext4"}}, budget)
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if want := under(root, "srv"); !slices.Equal(sc.Walk, want) || len(sc.Skipped) != 0 {
			t.Errorf("Walk = %q, Skipped = %+v", sc.Walk, sc.Skipped)
		}
	})

	t.Run("the root filesystem is never skipped for its size", func(t *testing.T) {
		root := makeTree(t, "usr/", "opt/")
		budget := fileBudget{Limit: 1000, Count: countsOf(t, map[string]uint64{root: 80_000_000})}
		sc, err := planScope(root, under(root, "usr", "opt"), []mount{{root, "ext4"}}, budget)
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if want := under(root, "usr", "opt"); !slices.Equal(sc.Walk, want) {
			t.Errorf("Walk = %q, want %q", sc.Walk, want)
		}
	})

	t.Run("a filesystem that does not say how many files it has is walked", func(t *testing.T) {
		root := makeTree(t, "srv/")
		srv := filepath.Join(root, "srv")
		budget := fileBudget{Limit: 1000, Count: countsOf(t, nil)}
		sc, err := planScope(root, under(root, "srv"), []mount{{root, "ext4"}, {srv, "btrfs"}}, budget)
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if want := under(root, "srv"); !slices.Equal(sc.Walk, want) {
			t.Errorf("Walk = %q, want %q", sc.Walk, want)
		}
	})

	t.Run("a network filesystem is never asked for its file count", func(t *testing.T) {
		root := makeTree(t, "export/")
		export := filepath.Join(root, "export")
		asked := false
		budget := fileBudget{Limit: 1000, Count: func(string) (uint64, bool) { asked = true; return 0, false }}
		sc, err := planScope(root, under(root, "export"), []mount{{root, "ext4"}, {export, "nfs4"}}, budget)
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if asked {
			t.Error("asked a network filesystem for its file count; on a dead server that call hangs")
		}
		if got := skipReasonFor(sc, export); !strings.Contains(got, "nfs4") {
			t.Errorf("reason = %q, want the filesystem type", got)
		}
	})

	t.Run("no limit means nothing is skipped for size", func(t *testing.T) {
		root := makeTree(t, "srv/")
		srv := filepath.Join(root, "srv")
		budget := fileBudget{Limit: 0, Count: countsOf(t, map[string]uint64{srv: 80_000_000})}
		sc, err := planScope(root, under(root, "srv"), []mount{{root, "ext4"}, {srv, "ext4"}}, budget)
		if err != nil {
			t.Fatalf("planScope: %v", err)
		}
		if len(sc.Skipped) != 0 {
			t.Errorf("Skipped = %+v, want none", sc.Skipped)
		}
	})
}

func TestBudgetFor(t *testing.T) {
	if got := budgetFor(2048); got != 524288 {
		t.Errorf("budgetFor(2048) = %d, want 524288", got)
	}
	if got := budgetFor(0); got != 0 {
		t.Errorf("no memory limit should mean no file limit, got %d", got)
	}
}

func TestFilesOnFilesystem(t *testing.T) {
	// Whatever filesystem the tests run on, the answer must be sane or
	// "does not say"; it must never be a nonsense number from a wrapped
	// subtraction.
	files, known := filesOnFilesystem(t.TempDir())
	if known && (files == 0 || files > 1<<40) {
		t.Errorf("implausible file count %d", files)
	}
	if _, known := filesOnFilesystem(filepath.Join(t.TempDir(), "absent")); known {
		t.Error("a path that does not exist cannot have a known count")
	}
}
