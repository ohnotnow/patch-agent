package main

import (
	"context"
	"fmt"

	_ "modernc.org/sqlite" // syft needs this to read the rpm database

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// scan catalogues the machine with syft, walking only what the scope allows.
func scan(ctx context.Context, sc scope) (*sbom.SBOM, error) {
	srcCfg := syft.DefaultGetSourceConfig().
		WithSources("dir").
		WithExcludeConfig(source.ExcludeConfig{Paths: sc.Excludes})

	src, err := syft.GetSource(ctx, "/", srcCfg)
	if err != nil {
		return nil, fmt.Errorf("open scan root: %w", err)
	}
	defer src.Close()

	cfg := syft.DefaultCreateSBOMConfig().
		WithTool("patch-agent", Version).
		// Keep a binary even when an OS package owns the file, so that an
		// nginx bundled inside another product is still reported as nginx.
		// The per-file "package contains file" records are left out: each
		// OS package already carries its own file list.
		WithRelationshipsConfig(cataloging.DefaultRelationshipsConfig().
			WithExcludeBinaryPackagesWithFileOwnershipOverlap(false).
			WithPackageFileOwnership(false)).
		// A directory scan reads only lockfiles by default. Add the
		// installed-package catalogers that an image scan would use.
		// Two catalogers are left out:
		//  - the kernel one reports every kernel module file as a package,
		//    and kernels are matched from the distro's own kernel packages;
		//  - the ELF package-note one makes syft delete a classifier's
		//    finding for every copy of a binary, noted or not, once one
		//    copy carries a note (so a bundled curl vanished when the
		//    distro's curl of the same version was in the scan).
		WithCatalogerSelection(cataloging.NewSelectionRequest().
			WithDefaults(pkgcataloging.ImageTag, pkgcataloging.DirectoryTag).
			WithRemovals("linux-kernel-cataloger", "elf-binary-package-cataloger")).
		// Do not read and hash every file a package owns.
		WithFilesConfig(filecataloging.DefaultConfig().
			WithSelection(file.NoFilesSelection))

	s, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("catalogue: %w", err)
	}
	return s, nil
}

// installedDebs lists the packages syft read from the dpkg database.
func installedDebs(s *sbom.SBOM) []installedDeb {
	var debs []installedDeb
	for _, p := range s.Artifacts.Packages.Sorted(pkg.DebPkg) {
		if entry, ok := p.Metadata.(pkg.DpkgDBEntry); ok {
			debs = append(debs, installedDeb{Name: p.Name, Version: p.Version, Architecture: entry.Architecture})
		}
	}
	return debs
}

func encodeInventory(s *sbom.SBOM) ([]byte, error) {
	return format.Encode(*s, syftjson.NewFormatEncoder())
}
