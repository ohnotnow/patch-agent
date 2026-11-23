package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// The agent runs as root on machines that are doing real work, and someone
// will one day start it by hand with no wrapper. So it keeps itself out of
// the way: lowest CPU and disk priority, first in line if the kernel must
// kill something for memory, and a limit on its own memory that it enforces
// by stopping.

// memoryCheckInterval is how often the agent looks at its own memory.
const memoryCheckInterval = 200 * time.Millisecond

// watchMemory makes the process stop itself before it holds more than
// limitKB of memory. It also tells Go's garbage collector to work harder as
// that limit approaches, so the limit is only reached by memory genuinely in
// use. read returns the memory held now, in KB. onExceed is called once, with
// that figure, when the limit is passed. The returned function ends the watch.
func watchMemory(limitKB int64, interval time.Duration, read func() (int64, error), onExceed func(heldKB int64)) (stop func()) {
	debug.SetMemoryLimit(limitKB * 1024 * 3 / 4)
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if held, err := read(); err == nil && held > limitKB {
					onExceed(held)
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

// residentMemoryKB reads how much memory this process holds right now.
func residentMemoryKB() (int64, error) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, err
	}
	return parseStatm(string(data), int64(os.Getpagesize()))
}

// parseStatm reads the resident set size, the second field of
// /proc/self/statm, which is counted in pages.
func parseStatm(statm string, pageSize int64) (int64, error) {
	fields := strings.Fields(statm)
	if len(fields) < 2 {
		return 0, fmt.Errorf("unrecognised statm: %q", statm)
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unrecognised statm: %q", statm)
	}
	return pages * pageSize / 1024, nil
}
