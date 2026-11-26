package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// extraKey is the top-level key the agent adds to syft's JSON. Grype
// ignores it.
const extraKey = "patchAgent"

// extra is everything the agent reports that syft does not.
type extra struct {
	AgentVersion  string    `json:"agentVersion"`
	SyftVersion   string    `json:"syftVersion"`
	CollectedAt   time.Time `json:"collectedAt"`
	RunningKernel string    `json:"runningKernel"`
	UptimeSeconds int64     `json:"uptimeSeconds"`
	// What this run cost the machine, so the cost can be watched fleet-wide.
	RunSeconds   int64       `json:"runSeconds"`
	PeakMemoryKB int64       `json:"peakMemoryKB"`
	Scope        scopeReport `json:"scope"`
	Listeners    []listener  `json:"listeners"`
	// Apt is absent on a machine that does not use apt.
	Apt *aptFacts `json:"apt,omitempty"`
	// Problems lists the parts that could not be collected. An inventory
	// with problems is partial, not clean.
	Problems []string `json:"problems"`
}

type scopeReport struct {
	Walked  []string  `json:"walked"`
	Skipped []skipped `json:"skipped"`
}

// collectExtra gathers the agent's own facts. A part that fails is recorded
// in Problems and the rest is still reported. The listening sockets are
// collected before the scan, because their app folders join the walk.
func collectExtra(procRoot, hostRoot string, sc scope, listeners []listener, listenErr error, debs []installedDeb, now time.Time) extra {
	x := extra{
		AgentVersion: Version,
		SyftVersion:  syftVersion(),
		CollectedAt:  now.UTC().Truncate(time.Second),
		Scope:        scopeReport{Walked: sc.Walk, Skipped: sc.Skipped},
		Listeners:    []listener{},
		Problems:     []string{},
	}
	problem := func(what string, err error) {
		x.Problems = append(x.Problems, what+": "+err.Error())
	}

	if release, err := os.ReadFile(filepath.Join(procRoot, "sys/kernel/osrelease")); err != nil {
		problem("running kernel", err)
	} else {
		x.RunningKernel = strings.TrimSpace(string(release))
	}

	if uptime, err := readUptime(filepath.Join(procRoot, "uptime")); err != nil {
		problem("uptime", err)
	} else {
		x.UptimeSeconds = uptime
	}

	if listenErr != nil {
		problem("listening sockets", listenErr)
	} else if listeners != nil {
		x.Listeners = listeners
	}

	apt, aptProblems := collectAptFacts(filepath.Join(hostRoot, "var/lib/apt/lists"), debs)
	x.Apt = apt
	x.Problems = append(x.Problems, aptProblems...)
	return x
}

func readUptime(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("%s is empty", path)
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return int64(seconds), nil
}

// peakMemoryKB is the most memory this process has held, as Linux reports it.
func peakMemoryKB() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return int64(usage.Maxrss)
}

// syftVersion reports the syft library this binary was built with.
func syftVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/anchore/syft" {
				return dep.Version
			}
		}
	}
	return "unknown"
}

// addExtra puts the agent's section into syft's JSON as one more top-level
// key, leaving everything syft wrote untouched.
func addExtra(inventory []byte, x extra) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(inventory, &doc); err != nil {
		return nil, fmt.Errorf("read syft's JSON: %w", err)
	}
	if _, clash := doc[extraKey]; clash {
		return nil, fmt.Errorf("syft's JSON already has a %q key", extraKey)
	}
	section, err := json.Marshal(x)
	if err != nil {
		return nil, err
	}
	doc[extraKey] = section
	return json.Marshal(doc)
}
