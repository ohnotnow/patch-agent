//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

const (
	lowestNice = 19
	// ioprio_set(2): "who" is a single thread, and the value is the idle
	// class (3) in the top three bits.
	ioprioWhoProcess = 1
	ioprioIdle       = 3 << 13
)

// stayOutOfTheWay lowers the agent's own CPU and disk priority and marks it
// as the first process to kill if the machine runs out of memory. It returns
// a line for each step that did not work; none of them stops the run.
//
// On Linux both priorities belong to a thread, not a process, so every
// thread that exists now is set. Threads started later inherit them. Call
// this before doing any work, while there are only a few.
func stayOutOfTheWay() []string {
	var problems []string

	threads, err := os.ReadDir("/proc/self/task")
	if err != nil {
		problems = append(problems, "could not list own threads to lower their priority: "+err.Error())
	}
	niceFailed, ioFailed := 0, 0
	for _, t := range threads {
		tid, err := strconv.Atoi(t.Name())
		if err != nil {
			continue
		}
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, tid, lowestNice); err != nil {
			niceFailed++
		}
		if _, _, errno := syscall.Syscall(syscall.SYS_IOPRIO_SET, ioprioWhoProcess, uintptr(tid), ioprioIdle); errno != 0 {
			ioFailed++
		}
	}
	if niceFailed > 0 {
		problems = append(problems, fmt.Sprintf("could not lower CPU priority on %d of %d threads", niceFailed, len(threads)))
	}
	if ioFailed > 0 {
		problems = append(problems, fmt.Sprintf("could not lower disk priority on %d of %d threads", ioFailed, len(threads)))
	}

	// 1000 is the highest score: if the kernel has to kill something to
	// free memory, it should be this scan and not a database.
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0o644); err != nil {
		problems = append(problems, "could not volunteer as the first process to kill when memory runs out: "+err.Error())
	}
	return problems
}
