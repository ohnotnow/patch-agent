package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These tables are in the form a little-endian machine prints them (every
// architecture the agent is built for is little-endian).
const tcpTable = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 283721 1 0000000000000000 100 0 0 10 0
   1: 3600007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   989        0 109178 1 0000000000000000 100 0 0 10 0
   2: 0F0200C0:0016 020200C0:C1F4 01 00000000:00000000 02:000A8C5B 00000000     0        0 290001 4 0000000000000000 20 4 30 10 -1
`

const tcp6Table = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 259858 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 100 0 0 10 0
`

const udpTable = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  288: 0A0200C0:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000   998        0 282280 2 0000000000000000 0
  300: 0100007F:D431 0100007F:0035 01 00000000:00000000 00:00000000 00000000   998        0 282299 2 0000000000000000 0
`

func TestParseSocketTable(t *testing.T) {
	t.Run("tcp keeps only listening sockets", func(t *testing.T) {
		got, err := parseSocketTable(strings.NewReader(tcpTable), "0A")
		if err != nil {
			t.Fatalf("parseSocketTable: %v", err)
		}
		want := []socketEntry{
			{"0.0.0.0", 8080, 283721},
			{"127.0.0.54", 53, 109178},
		}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("tcp6", func(t *testing.T) {
		got, err := parseSocketTable(strings.NewReader(tcp6Table), "0A")
		if err != nil {
			t.Fatalf("parseSocketTable: %v", err)
		}
		want := []socketEntry{
			{"::", 80, 259858},
			{"::1", 631, 31337},
		}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("udp keeps only unconnected sockets", func(t *testing.T) {
		got, err := parseSocketTable(strings.NewReader(udpTable), "07")
		if err != nil {
			t.Fatalf("parseSocketTable: %v", err)
		}
		want := []socketEntry{{"192.0.2.10", 68, 282280}}
		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a malformed line is an error", func(t *testing.T) {
		if _, err := parseSocketTable(strings.NewReader("   0: nonsense\n"), "0A"); err == nil {
			t.Error("expected an error")
		}
	})
}

// fakeProc builds a pretend /proc. Keys ending in "->" make a symlink to the
// value; any other key makes a file holding the value.
func fakeProc(t *testing.T, entries map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, value := range entries {
		link := strings.HasSuffix(name, "->")
		full := filepath.Join(root, strings.TrimSuffix(name, "->"))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		var err error
		if link {
			err = os.Symlink(value, full)
		} else {
			err = os.WriteFile(full, []byte(value), 0o644)
		}
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	return root
}

func writeProgram(t *testing.T, contents string) (path, sum string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "program")
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatalf("write program: %v", err)
	}
	digest := sha256.Sum256([]byte(contents))
	return path, hex.EncodeToString(digest[:])
}

func findListener(t *testing.T, listeners []listener, netns string, port int) listener {
	t.Helper()
	for _, l := range listeners {
		if l.NetNamespace == netns && l.Port == port {
			return l
		}
	}
	t.Fatalf("no listener on port %d in %q among %+v", port, netns, listeners)
	return listener{}
}

func TestCollectListeners(t *testing.T) {
	hostNginx, hostSum := writeProgram(t, "the host's nginx")
	containerNginx, containerSum := writeProgram(t, "a different nginx, inside a container")

	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	listening := func(addrPort, inode string) string {
		return "   0: " + addrPort + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 " + inode + " 1 0 100 0 0 10 0\n"
	}

	proc := fakeProc(t, map[string]string{
		"self/ns/net->": "net:[1]",
		"self/ns/mnt->": "mnt:[1]",

		// an nginx master and worker on the host, sharing one socket
		"10/ns/net->": "net:[1]",
		"10/ns/mnt->": "mnt:[1]",
		"10/exe->":    hostNginx,
		"10/fd/0->":   "/dev/null",
		"10/fd/5->":   "socket:[100]",
		"10/net/tcp":  header + listening("00000000:0050", "100") + listening("00000000:0801", "300") + listening("0100007F:0019", "400"),
		"11/ns/net->": "net:[1]",
		"11/ns/mnt->": "mnt:[1]",
		"11/exe->":    hostNginx,
		"11/fd/5->":   "socket:[100]",

		// a process whose program file has been replaced since it started
		"12/ns/net->": "net:[1]",
		"12/ns/mnt->": "mnt:[1]",
		"12/exe->":    "/usr/sbin/exim4 (deleted)",
		"12/fd/3->":   "socket:[400]",

		// an nginx in a container, on the same port in its own namespaces
		"20/ns/net->": "net:[2]",
		"20/ns/mnt->": "mnt:[2]",
		"20/exe->":    containerNginx,
		"20/fd/6->":   "socket:[200]",
		"20/net/tcp":  header + listening("00000000:0050", "200"),

		"not-a-pid/ignored": "",
	})

	listeners, err := collectListeners(proc, "/")
	if err != nil {
		t.Fatalf("collectListeners: %v", err)
	}
	if len(listeners) != 4 {
		t.Fatalf("got %d listeners, want 4: %+v", len(listeners), listeners)
	}

	t.Run("a shared socket lists every process holding it", func(t *testing.T) {
		l := findListener(t, listeners, hostNamespace, 80)
		want := []process{
			{PID: 10, Exe: hostNginx, SHA256: hostSum, ExeIsHostFile: true},
			{PID: 11, Exe: hostNginx, SHA256: hostSum, ExeIsHostFile: true},
		}
		if !slices.Equal(l.Processes, want) {
			t.Errorf("got %+v, want %+v", l.Processes, want)
		}
		if l.Protocol != "tcp" || l.Address != "0.0.0.0" {
			t.Errorf("got %s %s, want tcp 0.0.0.0", l.Protocol, l.Address)
		}
	})

	t.Run("a socket in another network namespace is found and labelled", func(t *testing.T) {
		l := findListener(t, listeners, "net:[2]", 80)
		if len(l.Processes) != 1 {
			t.Fatalf("got %+v, want one process", l.Processes)
		}
		p := l.Processes[0]
		if p.PID != 20 || p.Exe != containerNginx || p.SHA256 != containerSum {
			t.Errorf("got %+v", p)
		}
	})

	t.Run("a program is the host's file only when the host has that very file at that path", func(t *testing.T) {
		// A host with nothing at the program's path, as when the path only
		// exists inside a container.
		emptyHost := t.TempDir()
		got, err := collectListeners(proc, emptyHost)
		if err != nil {
			t.Fatalf("collectListeners: %v", err)
		}
		if p := findListener(t, got, "net:[2]", 80).Processes[0]; p.ExeIsHostFile {
			t.Errorf("nothing at that path on the host, but got %+v", p)
		}

		// A host with a different file at the same path, as when a container
		// and the host both have /usr/sbin/nginx.
		otherHost := t.TempDir()
		clash := filepath.Join(otherHost, containerNginx)
		if err := os.MkdirAll(filepath.Dir(clash), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(clash, []byte("the host's own, different, nginx"), 0o755); err != nil {
			t.Fatal(err)
		}
		got, err = collectListeners(proc, otherHost)
		if err != nil {
			t.Fatalf("collectListeners: %v", err)
		}
		p := findListener(t, got, "net:[2]", 80).Processes[0]
		if p.ExeIsHostFile {
			t.Errorf("a different file is at that path on the host, but got %+v", p)
		}
		if p.SHA256 != containerSum {
			t.Errorf("the hash must be of the file the process runs, got %s", p.SHA256)
		}
	})

	t.Run("a socket no process holds is still reported", func(t *testing.T) {
		l := findListener(t, listeners, hostNamespace, 2049)
		if l.Processes == nil || len(l.Processes) != 0 {
			t.Errorf("got %+v, want an empty list", l.Processes)
		}
	})

	t.Run("a replaced program file is flagged", func(t *testing.T) {
		l := findListener(t, listeners, hostNamespace, 25)
		if len(l.Processes) != 1 {
			t.Fatalf("got %+v, want one process", l.Processes)
		}
		p := l.Processes[0]
		if p.Exe != "/usr/sbin/exim4" || !p.ExeDeleted {
			t.Errorf("got exe %q deleted %v, want /usr/sbin/exim4 and deleted", p.Exe, p.ExeDeleted)
		}
		if l.Address != "127.0.0.1" {
			t.Errorf("got address %s, want 127.0.0.1", l.Address)
		}
	})
}
