package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCollectExtra(t *testing.T) {
	now := time.Date(2026, 11, 20, 15, 4, 5, 999, time.UTC)
	sc := scope{
		Walk:    []string{"/usr", "/opt"},
		Skipped: []skipped{{"/export", "not present"}},
	}

	t.Run("reports the kernel, uptime, scope and listeners", func(t *testing.T) {
		proc := fakeProc(t, map[string]string{
			"sys/kernel/osrelease": "7.0.0-43-generic\n",
			"uptime":               "93784.52 180000.10\n",
			"self/ns/net->":        "net:[1]",
			"self/ns/mnt->":        "mnt:[1]",
			"1/ns/net->":           "net:[1]",
			"1/ns/mnt->":           "mnt:[1]",
			"1/fd/3->":             "socket:[7]",
			"1/net/tcp":            "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7 1 0 100 0 0 10 0\n",
		})
		listeners, err := collectListeners(proc, "/")
		x := collectExtra(proc, "/", sc, listeners, err, nil, now)

		if x.RunningKernel != "7.0.0-43-generic" {
			t.Errorf("RunningKernel = %q", x.RunningKernel)
		}
		if x.UptimeSeconds != 93784 {
			t.Errorf("UptimeSeconds = %d, want 93784", x.UptimeSeconds)
		}
		if !x.CollectedAt.Equal(time.Date(2026, 11, 20, 15, 4, 5, 0, time.UTC)) {
			t.Errorf("CollectedAt = %s", x.CollectedAt)
		}
		if !slices.Equal(x.Scope.Walked, sc.Walk) || !slices.Equal(x.Scope.Skipped, sc.Skipped) {
			t.Errorf("Scope = %+v", x.Scope)
		}
		if len(x.Listeners) != 1 || x.Listeners[0].Port != 22 {
			t.Errorf("Listeners = %+v, want one on port 22", x.Listeners)
		}
		if len(x.Problems) != 0 {
			t.Errorf("Problems = %q, want none", x.Problems)
		}
	})

	t.Run("a part that cannot be read becomes a problem, not a failure", func(t *testing.T) {
		proc := fakeProc(t, map[string]string{"uptime": "12.5 20.0\n"})
		listeners, err := collectListeners(proc, "/")
		x := collectExtra(proc, "/", sc, listeners, err, nil, now)

		if x.UptimeSeconds != 12 {
			t.Errorf("UptimeSeconds = %d, want 12 (the readable part is still reported)", x.UptimeSeconds)
		}
		joined := strings.Join(x.Problems, "\n")
		for _, want := range []string{"running kernel", "listening sockets"} {
			if !strings.Contains(joined, want) {
				t.Errorf("Problems should mention %q, got %q", want, x.Problems)
			}
		}
		if x.Listeners == nil {
			t.Error("Listeners should be an empty list, not null")
		}
	})
}

func TestAddExtra(t *testing.T) {
	syftJSON := []byte(`{"artifacts":[{"name":"curl"}],"schema":{"version":"16.0.0"}}`)
	x := extra{AgentVersion: "test", RunningKernel: "7.0.0", Listeners: []listener{}, Problems: []string{}}

	t.Run("adds one key and leaves syft's alone", func(t *testing.T) {
		out, err := addExtra(syftJSON, x)
		if err != nil {
			t.Fatalf("addExtra: %v", err)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("output is not JSON: %v", err)
		}
		if len(doc) != 3 {
			t.Errorf("got %d top-level keys, want 3", len(doc))
		}
		if string(doc["artifacts"]) != `[{"name":"curl"}]` {
			t.Errorf("artifacts changed: %s", doc["artifacts"])
		}
		var got extra
		if err := json.Unmarshal(doc[extraKey], &got); err != nil {
			t.Fatalf("extra section is not readable: %v", err)
		}
		if got.RunningKernel != "7.0.0" || got.AgentVersion != "test" {
			t.Errorf("extra section = %+v", got)
		}
	})

	t.Run("refuses to overwrite an existing key", func(t *testing.T) {
		if _, err := addExtra([]byte(`{"patchAgent":{}}`), x); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("rejects input that is not JSON", func(t *testing.T) {
		if _, err := addExtra([]byte("not json"), x); err == nil {
			t.Error("expected an error")
		}
	})
}
