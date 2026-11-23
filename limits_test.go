package main

import (
	"errors"
	"math"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseStatm(t *testing.T) {
	// size resident shared text lib data dt, in pages
	got, err := parseStatm("412345 131072 2048 5000 0 90000 0\n", 4096)
	if err != nil || got != 131072*4 {
		t.Errorf("got %d KB, %v; want %d KB", got, err, 131072*4)
	}
	if got, _ := parseStatm("10 100 0 0 0 0 0", 16384); got != 1600 {
		t.Errorf("with 16 KB pages got %d KB, want 1600", got)
	}
	for _, bad := range []string{"", "12345", "a b c"} {
		if _, err := parseStatm(bad, 4096); err == nil {
			t.Errorf("parseStatm(%q) should be an error", bad)
		}
	}
}

func TestWatchMemory(t *testing.T) {
	// watchMemory changes the collector's limit for the whole process.
	t.Cleanup(func() { debug.SetMemoryLimit(math.MaxInt64) })

	t.Run("stops the run once the limit is passed", func(t *testing.T) {
		var held atomic.Int64
		held.Store(500)
		exceeded := make(chan int64, 1)
		stop := watchMemory(1000, time.Millisecond,
			func() (int64, error) { return held.Load(), nil },
			func(kb int64) { exceeded <- kb })
		defer stop()

		select {
		case kb := <-exceeded:
			t.Fatalf("stopped at %d KB, under the limit", kb)
		case <-time.After(20 * time.Millisecond):
		}

		held.Store(1500)
		select {
		case kb := <-exceeded:
			if kb != 1500 {
				t.Errorf("reported %d KB, want 1500", kb)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("did not stop after the limit was passed")
		}
	})

	t.Run("a reading that fails is not treated as over the limit", func(t *testing.T) {
		exceeded := make(chan int64, 1)
		stop := watchMemory(1000, time.Millisecond,
			func() (int64, error) { return 999999, errors.New("cannot read") },
			func(kb int64) { exceeded <- kb })
		defer stop()
		select {
		case <-exceeded:
			t.Fatal("stopped on a failed reading")
		case <-time.After(20 * time.Millisecond):
		}
	})

	t.Run("stopping the watch ends it", func(t *testing.T) {
		var held atomic.Int64
		exceeded := make(chan int64, 1)
		stop := watchMemory(1000, time.Millisecond,
			func() (int64, error) { return held.Load(), nil },
			func(kb int64) { exceeded <- kb })
		stop()
		time.Sleep(5 * time.Millisecond)
		held.Store(5000)
		select {
		case <-exceeded:
			t.Fatal("still watching after stop")
		case <-time.After(20 * time.Millisecond):
		}
	})

	t.Run("asks the garbage collector to keep under the limit", func(t *testing.T) {
		stop := watchMemory(2*1024*1024, time.Hour, func() (int64, error) { return 0, nil }, func(int64) {})
		defer stop()
		if got, want := debug.SetMemoryLimit(-1), int64(2*1024*1024*1024*3/4); got != want {
			t.Errorf("collector limit = %d bytes, want %d", got, want)
		}
	})
}
