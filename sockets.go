package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// hostNamespace is what a namespace field says when it is the agent's own.
const hostNamespace = "host"

// listener is one listening socket and the processes holding it open.
type listener struct {
	Protocol string `json:"protocol"` // "tcp" or "udp"
	Address  string `json:"address"`
	Port     int    `json:"port"`
	// NetNamespace is "host", or the kernel's name for another network
	// namespace (a container's, usually), such as "net:[4026532287]".
	NetNamespace string    `json:"netNamespace"`
	Processes    []process `json:"processes"`
}

type process struct {
	PID int `json:"pid"`
	// Exe is the program's path as that process sees it, which inside a
	// container is not a path on the host.
	Exe        string `json:"exe,omitempty"`
	ExeDeleted bool   `json:"exeDeleted,omitempty"` // the file was replaced or removed since the process started
	// ExeIsHostFile says whether the host's file at the path Exe is the
	// very file the process is running. Only then may Exe be looked up
	// among the host's packages. It is false for a process in a container
	// and for a program replaced since it started.
	ExeIsHostFile bool   `json:"exeIsHostFile"`
	SHA256        string `json:"sha256,omitempty"`
	// Unit is the systemd unit or container scope the process runs in.
	Unit string `json:"unit,omitempty"`
	// Cwd and FileArg are paths as the process sees them. FileArg is the
	// first command-line argument that is a file: the script, for an
	// interpreter, but it can as easily be a config or data file. No other
	// part of the command line is reported.
	Cwd     string   `json:"cwd,omitempty"`
	FileArg string   `json:"fileArgument,omitempty"`
	Project *project `json:"project,omitempty"`
	Problem string   `json:"problem,omitempty"`
}

type socketEntry struct {
	Address string
	Port    int
	Inode   uint64
}

// The socket tables to read in each network namespace, and the state that
// means "waiting for traffic": LISTEN for TCP, unconnected for UDP.
var socketTables = []struct{ file, protocol, state string }{
	{"tcp", "tcp", "0A"},
	{"tcp6", "tcp", "0A"},
	{"udp", "udp", "07"},
	{"udp6", "udp", "07"},
}

// collectListeners reads the listening sockets of every network namespace
// that has a process in it, and works out which processes hold each one.
// It only reads files under procRoot ("/proc"), and looks at program files
// under hostRoot ("/"); it runs nothing.
func collectListeners(procRoot, hostRoot string) ([]listener, error) {
	pids, err := listPIDs(procRoot)
	if err != nil {
		return nil, err
	}
	selfNet, err := os.Readlink(filepath.Join(procRoot, "self/ns/net"))
	if err != nil {
		return nil, fmt.Errorf("read own network namespace: %w", err)
	}

	firstPIDIn := map[string]int{} // network namespace -> a process inside it
	holders := map[uint64][]int{}  // socket inode -> processes with it open
	var namespaces []string
	for _, pid := range pids {
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		ns, err := os.Readlink(filepath.Join(dir, "ns/net"))
		if err != nil {
			continue // the process has gone, or is not ours to see
		}
		if _, seen := firstPIDIn[ns]; !seen {
			firstPIDIn[ns] = pid
			namespaces = append(namespaces, ns)
		}
		for _, inode := range socketInodes(filepath.Join(dir, "fd")) {
			if !slices.Contains(holders[inode], pid) {
				holders[inode] = append(holders[inode], pid)
			}
		}
	}

	describe := newProcessDescriber(procRoot, hostRoot)
	var listeners []listener
	for _, ns := range namespaces {
		netDir := filepath.Join(procRoot, strconv.Itoa(firstPIDIn[ns]), "net")
		for _, table := range socketTables {
			f, err := os.Open(filepath.Join(netDir, table.file))
			if err != nil {
				continue // no IPv6, or the process has gone
			}
			entries, err := parseSocketTable(f, table.state)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("%s in %s: %w", table.file, ns, err)
			}
			for _, e := range entries {
				l := listener{
					Protocol:     table.protocol,
					Address:      e.Address,
					Port:         e.Port,
					NetNamespace: namespaceLabel(ns, selfNet),
					Processes:    []process{},
				}
				for _, pid := range holders[e.Inode] {
					l.Processes = append(l.Processes, describe(pid))
				}
				listeners = append(listeners, l)
			}
		}
	}
	return listeners, nil
}

func namespaceLabel(ns, own string) string {
	if ns == own {
		return hostNamespace
	}
	return ns
}

func listPIDs(procRoot string) ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("list processes: %w", err)
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids, nil
}

// socketInodes returns the sockets among a process's open files. Each is a
// link reading "socket:[12345]".
func socketInodes(fdDir string) []uint64 {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var inodes []uint64
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		number, ok := strings.CutPrefix(target, "socket:[")
		if !ok {
			continue
		}
		if inode, err := strconv.ParseUint(strings.TrimSuffix(number, "]"), 10, 64); err == nil {
			inodes = append(inodes, inode)
		}
	}
	return inodes
}

// parseSocketTable reads /proc/net/tcp, tcp6, udp or udp6 and returns the
// sockets in the wanted state.
func parseSocketTable(r io.Reader, wantState string) ([]socketEntry, error) {
	var entries []socketEntry
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// "sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode ..."
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || fields[0] == "sl" {
			continue
		}
		if len(fields) < 10 {
			return nil, fmt.Errorf("unrecognised socket line: %q", sc.Text())
		}
		if fields[3] != wantState {
			continue
		}
		address, port, err := parseSocketAddress(fields[1])
		if err != nil {
			return nil, err
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("socket inode in %q: %w", sc.Text(), err)
		}
		entries = append(entries, socketEntry{Address: address, Port: port, Inode: inode})
	}
	return entries, sc.Err()
}

// parseSocketAddress decodes the kernel's "0100007F:1F90" form. The address
// is printed as 32-bit words in the machine's own byte order.
func parseSocketAddress(s string) (string, int, error) {
	hexAddr, hexPort, found := strings.Cut(s, ":")
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if !found || err != nil || (len(hexAddr) != 8 && len(hexAddr) != 32) {
		return "", 0, fmt.Errorf("unrecognised socket address: %q", s)
	}
	printed, err := hex.DecodeString(hexAddr)
	if err != nil {
		return "", 0, fmt.Errorf("unrecognised socket address: %q", s)
	}
	raw := make([]byte, len(printed))
	for i := 0; i < len(printed); i += 4 {
		binary.NativeEndian.PutUint32(raw[i:], binary.BigEndian.Uint32(printed[i:]))
	}
	addr, _ := netip.AddrFromSlice(raw)
	return addr.String(), int(port), nil
}

// newProcessDescriber returns a function that reports a process's program
// file and its hash. Each distinct file is hashed once per run.
func newProcessDescriber(procRoot, hostRoot string) func(pid int) process {
	type hashed struct {
		info os.FileInfo
		sum  string
	}
	var seen []hashed
	described := map[int]process{}

	return func(pid int) process {
		if p, ok := described[pid]; ok {
			return p
		}
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		p := process{PID: pid}
		defer func() { described[pid] = p }()

		ctx := describeContext(procRoot, pid)
		p.Unit, p.Cwd, p.FileArg, p.Project = ctx.Unit, ctx.Cwd, ctx.FileArg, ctx.Project

		exe, err := os.Readlink(filepath.Join(dir, "exe"))
		if err != nil {
			p.Problem = "cannot read the program path: " + err.Error()
			return p
		}
		p.Exe, p.ExeDeleted = strings.CutSuffix(exe, " (deleted)")

		// Opening the link, not the path it names, reaches the file the
		// process is really running: inside a container, or since deleted.
		f, err := os.Open(filepath.Join(dir, "exe"))
		if err != nil {
			p.Problem = "cannot open the program file: " + err.Error()
			return p
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			p.Problem = "cannot stat the program file: " + err.Error()
			return p
		}
		if onHost, err := os.Stat(filepath.Join(hostRoot, p.Exe)); err == nil {
			p.ExeIsHostFile = os.SameFile(info, onHost)
		}
		for _, h := range seen {
			if os.SameFile(h.info, info) {
				p.SHA256 = h.sum
				return p
			}
		}
		sum := sha256.New()
		if _, err := io.Copy(sum, f); err != nil {
			p.Problem = "cannot read the program file: " + err.Error()
			return p
		}
		p.SHA256 = hex.EncodeToString(sum.Sum(nil))
		seen = append(seen, hashed{info, p.SHA256})
		return p
	}
}
