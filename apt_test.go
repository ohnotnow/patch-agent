package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func release(fields ...string) string {
	return "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n" +
		strings.Join(fields, "\n") +
		"\nDate: Thu, 19 Nov 2026 10:00:00 UTC\nSHA256:\n 0123abcd 1234 main/binary-arm64/Packages\n"
}

func stanza(pkg, version, arch string) string {
	return "Package: " + pkg + "\nPriority: optional\nVersion: " + version +
		"\nDepends: libc6 (>= 2.34)\nArchitecture: " + arch +
		"\nDescription: something\n with a second line\n\n"
}

func writeLists(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func findDeb(t *testing.T, facts *aptFacts, name string) debFacts {
	t.Helper()
	for _, d := range facts.Debs {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("no facts for %s", name)
	return debFacts{}
}

func repoIndex(t *testing.T, facts *aptFacts, name string) int {
	t.Helper()
	i := slices.IndexFunc(facts.Repos, func(r aptRepo) bool { return r.Name == name })
	if i < 0 {
		t.Fatalf("no repo named %s among %+v", name, facts.Repos)
	}
	return i
}

// versionsIn returns the versions a deb's facts list for one repo.
func versionsIn(d debFacts, repo int) []string {
	for _, l := range d.Listed {
		if l.Repo == repo {
			return l.Versions
		}
	}
	return nil
}

func TestCollectAptFacts(t *testing.T) {
	const (
		distro  = "archive.example_ubuntu_dists_noble"
		updates = "archive.example_ubuntu_dists_noble-updates"
		third   = "third.example_php_dists_noble"
	)
	dir := writeLists(t, map[string]string{
		distro + "_InRelease":  release("Origin: Ubuntu", "Label: Ubuntu", "Suite: noble", "Codename: noble"),
		updates + "_InRelease": release("Origin: Ubuntu", "Label: Ubuntu", "Suite: noble-updates", "Codename: noble"),
		third + "_InRelease":   release("Origin: deb.sury.org", "Suite: noble", "Codename: noble"),

		distro + "_main_binary-arm64_Packages": stanza("curl", "8.5.0-2ubuntu10", "arm64") +
			stanza("php-common", "2:93ubuntu1", "all") + stanza("never-installed", "1.0", "arm64"),
		distro + "_main_binary-armhf_Packages":  stanza("curl", "8.5.0-2ubuntu10+armhf-only", "armhf"),
		updates + "_main_binary-arm64_Packages": stanza("curl", "8.5.0-2ubuntu10.6", "arm64"),
		third + "_main_binary-arm64_Packages": stanza("php8.3-cli", "8.3.1-1+third", "arm64") +
			stanza("php8.3-cli", "8.3.2-1+third", "arm64") + stanza("php-common", "2:95+third", "all"),

		// a repo with no release file, and a list apt kept compressed
		"local.example_repo_Packages":                           stanza("site-tool", "1.0", "arm64"),
		"zipped.example_dists_x_main_binary-arm64_Packages.lz4": "not readable",
		"lock": "",
	})
	installed := []installedDeb{
		{"curl", "8.5.0-2ubuntu10.4", "arm64"},   // a distro build that has since been superseded
		{"php8.3-cli", "8.3.2-1+third", "arm64"}, // from the third-party repo
		{"php-common", "2:95+third", "all"},      // third-party build of a name the distro also has
		{"hand-built", "1.0", "arm64"},           // in no repo at all
		{"site-tool", "1.0", "arm64"},            // from the repo with no release file
	}

	facts, problems := collectAptFacts(dir, installed)
	if facts == nil {
		t.Fatal("got no facts")
	}
	iDistro, iUpdates, iThird := repoIndex(t, facts, distro), repoIndex(t, facts, updates), repoIndex(t, facts, third)
	iLocal := repoIndex(t, facts, "local.example_repo")

	t.Run("repos carry their release fields", func(t *testing.T) {
		want := aptRepo{Name: updates, Origin: "Ubuntu", Label: "Ubuntu", Suite: "noble-updates", Codename: "noble"}
		if facts.Repos[iUpdates] != want {
			t.Errorf("got %+v, want %+v", facts.Repos[iUpdates], want)
		}
		if got := facts.Repos[iThird]; got.Origin != "deb.sury.org" || got.Label != "" {
			t.Errorf("got %+v", got)
		}
		if got := facts.Repos[iLocal]; got.Origin != "" {
			t.Errorf("a repo with no release file has no origin, got %+v", got)
		}
		if facts.ListsUpdated == nil || time.Since(*facts.ListsUpdated) > time.Hour {
			t.Errorf("ListsUpdated = %v, want about now", facts.ListsUpdated)
		}
	})

	t.Run("a superseded distro build: version in no repo, name listed by the distro", func(t *testing.T) {
		d := findDeb(t, facts, "curl")
		if len(d.InstalledVersionIn) != 0 {
			t.Errorf("InstalledVersionIn = %v, want none", d.InstalledVersionIn)
		}
		if got := versionsIn(d, iDistro); !slices.Equal(got, []string{"8.5.0-2ubuntu10"}) {
			t.Errorf("distro versions = %v (another architecture's build must not be counted)", got)
		}
		if got := versionsIn(d, iUpdates); !slices.Equal(got, []string{"8.5.0-2ubuntu10.6"}) {
			t.Errorf("updates versions = %v", got)
		}
	})

	t.Run("a third-party package: version found in its repo, every listed version reported", func(t *testing.T) {
		d := findDeb(t, facts, "php8.3-cli")
		if !slices.Equal(d.InstalledVersionIn, []int{iThird}) {
			t.Errorf("InstalledVersionIn = %v, want [%d]", d.InstalledVersionIn, iThird)
		}
		if got := versionsIn(d, iThird); !slices.Equal(got, []string{"8.3.1-1+third", "8.3.2-1+third"}) {
			t.Errorf("versions = %v", got)
		}
		if len(d.Listed) != 1 {
			t.Errorf("Listed = %+v, want only the third-party repo", d.Listed)
		}
	})

	t.Run("a third-party build of a name the distro also ships", func(t *testing.T) {
		d := findDeb(t, facts, "php-common")
		if !slices.Equal(d.InstalledVersionIn, []int{iThird}) {
			t.Errorf("InstalledVersionIn = %v", d.InstalledVersionIn)
		}
		if got := versionsIn(d, iDistro); !slices.Equal(got, []string{"2:93ubuntu1"}) {
			t.Errorf("distro versions = %v", got)
		}
	})

	t.Run("a package in no repo has empty lists, not missing ones", func(t *testing.T) {
		d := findDeb(t, facts, "hand-built")
		if d.InstalledVersionIn == nil || d.Listed == nil || len(d.InstalledVersionIn)+len(d.Listed) != 0 {
			t.Errorf("got %+v", d)
		}
	})

	t.Run("a repo with no release file still counts", func(t *testing.T) {
		if d := findDeb(t, facts, "site-tool"); !slices.Equal(d.InstalledVersionIn, []int{iLocal}) {
			t.Errorf("InstalledVersionIn = %v, want [%d]", d.InstalledVersionIn, iLocal)
		}
	})

	t.Run("a compressed list is reported as a problem, not ignored", func(t *testing.T) {
		if len(problems) != 1 || !strings.Contains(problems[0], "compressed") {
			t.Errorf("problems = %q", problems)
		}
	})

	t.Run("a machine without apt gives nothing", func(t *testing.T) {
		facts, problems := collectAptFacts(filepath.Join(t.TempDir(), "absent"), installed)
		if facts != nil || problems != nil {
			t.Errorf("got %+v, %q", facts, problems)
		}
	})
}
