package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"
)

// Version is overwritten at release time with -ldflags.
var Version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "patch-agent:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("patch-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("output", "", "write the inventory to this `file` instead of standard output")
	timeout := fs.Duration("timeout", 15*time.Minute, "give up if the whole run takes longer than this")
	maxMemoryMB := fs.Int64("max-memory", 2048, "stop if the agent holds more than this many `MB` of memory (0 for no limit)")
	maxFiles := fs.Uint64("max-files", 0, "skip any filesystem holding more than this many `files` (0 works it out from --max-memory)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintln(stdout, "patch-agent", Version)
		return nil
	}

	// Before any work: lowest CPU and disk priority, and a memory limit.
	limitProblems := stayOutOfTheWay()
	if *maxMemoryMB > 0 {
		stopWatching := watchMemory(*maxMemoryMB*1024, memoryCheckInterval, residentMemoryKB, func(heldKB int64) {
			fmt.Fprintf(stderr, "patch-agent: holding %d MB of memory, over the %d MB limit, giving up without writing an inventory (raise it with --max-memory)\n",
				heldKB/1024, *maxMemoryMB)
			os.Exit(3)
		})
		defer stopWatching()
	}

	// syft lists each excluded directory once before skipping it, so a dead
	// network mount can hang the walk in a system call that no context can
	// cancel. Exiting the process is the only limit that always works.
	watchdog := time.AfterFunc(*timeout, func() {
		fmt.Fprintf(stderr, "patch-agent: not finished after %s, giving up without writing an inventory\n", *timeout)
		os.Exit(2)
	})
	defer watchdog.Stop()

	mountinfo, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("read mounts (patch-agent only runs on Linux): %w", err)
	}
	mounts, err := parseMountinfo(mountinfo)
	mountinfo.Close()
	if err != nil {
		return err
	}

	budget := fileBudget{Limit: *maxFiles, Count: filesOnFilesystem}
	if budget.Limit == 0 {
		budget.Limit = budgetFor(*maxMemoryMB)
	}
	// Listening sockets first: only /proc is read, and each listener's app
	// folder or jar joins the walk.
	listeners, listenErr := collectListeners("/proc", "/")
	limitAppPaths(listeners, resolvedPaths(defaultScanPaths), mounts, appFileAllowance, countFiles)
	sc, err := planScope("/", slices.Concat(defaultScanPaths, appPathsToWalk(listeners)), mounts, budget)
	if err != nil {
		return err
	}
	noteAppScope(listeners, sc)
	for _, p := range sc.Walk {
		fmt.Fprintln(stderr, "walk:", p)
	}
	for _, s := range sc.Skipped {
		fmt.Fprintf(stderr, "skip: %s (%s)\n", s.Path, s.Reason)
	}
	fmt.Fprintf(stderr, "excluded from the walk: %d paths\n", len(sc.Excludes)/2) // two patterns per path
	var reported []string
	for _, l := range listeners {
		for _, p := range l.Processes {
			if p.AppPath != "" && p.AppSkipped != "" && !slices.Contains(reported, p.AppPath) {
				reported = append(reported, p.AppPath)
				fmt.Fprintf(stderr, "app not walked: %s (%s)\n", p.AppPath, p.AppSkipped)
			}
		}
	}

	start := time.Now()
	inventory, err := scan(context.Background(), sc)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "found %d packages in %s\n",
		inventory.Artifacts.Packages.PackageCount(), time.Since(start).Round(time.Millisecond))

	encoded, err := encodeInventory(inventory)
	if err != nil {
		return fmt.Errorf("encode inventory: %w", err)
	}
	encoded, err = stripFreeText(encoded)
	if err != nil {
		return fmt.Errorf("remove free text: %w", err)
	}

	x := collectExtra("/proc", "/", sc, listeners, listenErr, installedDebs(inventory), time.Now())
	x.Problems = append(x.Problems, limitProblems...)
	x.RunSeconds = int64(time.Since(start).Seconds())
	x.PeakMemoryKB = peakMemoryKB()
	fmt.Fprintf(stderr, "found %d listening sockets, running kernel %s\n", len(x.Listeners), x.RunningKernel)
	if x.Apt != nil {
		fmt.Fprintf(stderr, "read apt's lists for %d debs from %d repos\n", len(x.Apt.Debs), len(x.Apt.Repos))
	}
	fmt.Fprintf(stderr, "took %ds, peak memory %d MB\n", x.RunSeconds, x.PeakMemoryKB/1024)
	for _, p := range x.Problems {
		fmt.Fprintln(stderr, "problem:", p)
	}
	encoded, err = addExtra(encoded, x)
	if err != nil {
		return fmt.Errorf("add the agent's section: %w", err)
	}
	if *output == "" {
		_, err = stdout.Write(encoded)
		return err
	}
	return os.WriteFile(*output, encoded, 0o600)
}
