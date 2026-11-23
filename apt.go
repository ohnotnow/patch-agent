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
	"strings"
	"time"
)

// aptFacts is what apt's own list files say about where each installed deb
// could have come from. dpkg records no origin, so this is the only source.
// The agent reports the facts; deciding what they mean is for the central
// service.
type aptFacts struct {
	// ListsUpdated is when the newest release file was last fetched. Old
	// lists make everything below less trustworthy.
	ListsUpdated *time.Time `json:"listsUpdated,omitempty"`
	Repos        []aptRepo  `json:"repos"`
	Debs         []debFacts `json:"debs"`
}

// aptRepo is one release of one configured repository.
type aptRepo struct {
	// Name is the list files' common prefix, such as
	// "deb.debian.org_debian_dists_bookworm-updates".
	Name     string `json:"name"`
	Origin   string `json:"origin,omitempty"`
	Label    string `json:"label,omitempty"`
	Suite    string `json:"suite,omitempty"`
	Codename string `json:"codename,omitempty"`
}

type debFacts struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	// InstalledVersionIn lists the repos (indexes into Repos) that offer
	// exactly the installed version. Empty means apt cannot say where this
	// package came from.
	InstalledVersionIn []int `json:"installedVersionIn"`
	// Listed is every version of this package name that each repo offers
	// for this architecture. Empty means no configured repo has a package
	// of this name at all.
	Listed []debListing `json:"listed"`
}

type debListing struct {
	Repo     int      `json:"repo"`
	Versions []string `json:"versions"`
}

type installedDeb struct {
	Name, Version, Architecture string
}

// collectAptFacts reads apt's list files under listsDir. It runs nothing and
// needs no network. A machine without apt gives nil.
func collectAptFacts(listsDir string, installed []installedDeb) (*aptFacts, []string) {
	entries, err := os.ReadDir(listsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []string{"apt lists: " + err.Error()}
	}

	facts := &aptFacts{Repos: []aptRepo{}, Debs: []debFacts{}}
	var problems []string
	var packagesFiles []string
	compressed := 0
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, "_InRelease"), strings.HasSuffix(name, "_Release"):
			repo := aptRepo{Name: name[:strings.LastIndex(name, "_")]}
			if slices.ContainsFunc(facts.Repos, func(r aptRepo) bool { return r.Name == repo.Name }) {
				continue // both an InRelease and a Release for the same repo
			}
			if err := readRelease(filepath.Join(listsDir, name), &repo); err != nil {
				problems = append(problems, fmt.Sprintf("apt release file %s: %v", name, err))
			}
			facts.Repos = append(facts.Repos, repo)
			if info, err := e.Info(); err == nil {
				if modified := info.ModTime().UTC().Truncate(time.Second); facts.ListsUpdated == nil || modified.After(*facts.ListsUpdated) {
					facts.ListsUpdated = &modified
				}
			}
		case strings.HasSuffix(name, "_Packages"):
			packagesFiles = append(packagesFiles, name)
		case strings.Contains(name, "_Packages."):
			compressed++
		}
	}
	if compressed > 0 {
		problems = append(problems, fmt.Sprintf("apt lists: %d compressed package lists were not read", compressed))
	}

	wanted := map[string]bool{}
	for _, d := range installed {
		wanted[d.Name] = true
	}

	type offer struct{ version, architecture string }
	offers := map[int]map[string][]offer{} // repo index -> package name -> what it offers
	for _, name := range packagesFiles {
		repo := repoFor(facts, name)
		if offers[repo] == nil {
			offers[repo] = map[string][]offer{}
		}
		f, err := os.Open(filepath.Join(listsDir, name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("apt package list %s: %v", name, err))
			continue
		}
		err = scanPackages(f, wanted, func(pkg, version, architecture string) {
			offers[repo][pkg] = append(offers[repo][pkg], offer{version, architecture})
		})
		f.Close()
		if err != nil {
			problems = append(problems, fmt.Sprintf("apt package list %s: %v", name, err))
		}
	}

	for _, d := range installed {
		deb := debFacts{
			Name: d.Name, Version: d.Version, Architecture: d.Architecture,
			InstalledVersionIn: []int{}, Listed: []debListing{},
		}
		for repo := range facts.Repos {
			var versions []string
			for _, o := range offers[repo][d.Name] {
				sameArch := o.architecture == d.Architecture || o.architecture == "all" || d.Architecture == "all"
				if sameArch && !slices.Contains(versions, o.version) {
					versions = append(versions, o.version)
				}
			}
			if len(versions) == 0 {
				continue
			}
			slices.Sort(versions)
			deb.Listed = append(deb.Listed, debListing{Repo: repo, Versions: versions})
			if slices.Contains(versions, d.Version) {
				deb.InstalledVersionIn = append(deb.InstalledVersionIn, repo)
			}
		}
		facts.Debs = append(facts.Debs, deb)
	}
	return facts, problems
}

// repoFor returns the index of the repo a package list belongs to: the one
// whose name is the longest prefix of the list's file name. A list with no
// release file gets a repo of its own, with no origin.
func repoFor(facts *aptFacts, packagesFile string) int {
	best := -1
	for i, r := range facts.Repos {
		if strings.HasPrefix(packagesFile, r.Name+"_") && (best < 0 || len(r.Name) > len(facts.Repos[best].Name)) {
			best = i
		}
	}
	if best >= 0 {
		return best
	}
	facts.Repos = append(facts.Repos, aptRepo{Name: strings.TrimSuffix(packagesFile, "_Packages")})
	return len(facts.Repos) - 1
}

// readRelease fills in the identifying fields from an InRelease or Release
// file. They sit in the first few lines, before the long checksum lists.
func readRelease(path string, repo *aptRepo) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 64<<10))
	for sc.Scan() {
		key, value, found := strings.Cut(sc.Text(), ": ")
		if !found {
			continue
		}
		switch key {
		case "Origin":
			repo.Origin = value
		case "Label":
			repo.Label = value
		case "Suite":
			repo.Suite = value
		case "Codename":
			repo.Codename = value
		}
	}
	return nil // a release file cut short by the limit still gave its header
}

// scanPackages reads an apt Packages file and calls found for every stanza
// whose package name is wanted.
func scanPackages(r io.Reader, wanted map[string]bool, found func(pkg, version, architecture string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20) // dependency lines can be very long
	var pkg, version, architecture string
	emit := func() {
		if pkg != "" && version != "" && wanted[pkg] {
			found(pkg, version, architecture)
		}
		pkg, version, architecture = "", "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			emit()
		case strings.HasPrefix(line, "Package: "):
			pkg = line[len("Package: "):]
		case strings.HasPrefix(line, "Version: "):
			version = line[len("Version: "):]
		case strings.HasPrefix(line, "Architecture: "):
			architecture = line[len("Architecture: "):]
		}
	}
	emit()
	return sc.Err()
}
