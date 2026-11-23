# Technical Overview

Last updated: 2026-11-20

This describes the code as it stands. Why it is this way, what was tested
and what is still undecided live in the `ant` notebook; the last section
says where.

## What This Is

A prototype agent that runs as root on a Linux machine, records what
software is installed and what is listening on the network, and writes one
JSON inventory for a central service to judge. It observes and reports. It
does no vulnerability matching, changes nothing on the machine, and never
runs a program to find out what it is.

## Stack

- Go 1.27.4, a single static binary (`CGO_ENABLED=0`), about 80 MB
- `github.com/anchore/syft` v1.57.1, used as a library for cataloguing
- `modernc.org/sqlite` (syft needs it to read the rpm database)
- `github.com/BurntSushi/toml` (reading `pyproject.toml` and `Cargo.toml`)
- Standard library `flag` and `testing` only; no CLI or test frameworks

Grype is NOT part of the agent. It runs centrally against the inventory.

## Files

Flat `package main` at the repo root. Each file has a `_test.go` beside it
except `main.go`, `scan.go` and the two platform-specific limits files.

| File | Job |
|---|---|
| `main.go` | Flags, the time and memory limits, the order of a run, writing the file |
| `scope.go` | Decides what to walk: the path list, the filesystem-type allowlist, the syft exclude patterns |
| `scan.go` | The syft calls and settings; lists installed debs from syft's result |
| `redact.go` | Removes free-text fields from syft's package metadata |
| `sockets.go` | Listening sockets and the processes holding them, from `/proc` |
| `project.go` | What a listening process is: unit, working directory, project manifest, git remote |
| `apt.go` | What apt's list files say about each installed deb's origin |
| `extra.go` | Assembles the agent's own section and merges it into syft's JSON |
| `limits.go`, `limits_linux.go`, `limits_other.go` | Lowering its own priority and watching its own memory |

## What a Run Does

1. Parse flags. Lower CPU and disk priority, volunteer as the first
   process to kill if memory runs out, start the memory and time watches.
2. Read `/proc/self/mountinfo` and plan the scope (`planScope`).
3. Run ONE syft scan rooted at `/`, with exclude patterns that keep it to
   the planned paths (`scan`).
4. Encode as syft-json and strip free-text metadata (`stripFreeText`).
5. Collect the agent's own facts (`collectExtra`): running kernel, uptime,
   listeners, apt facts. A part that fails is recorded under `problems`
   and the rest still goes out.
6. Add the `patchAgent` key and write the file with mode 0600.

## Flags and Exit Codes

| Flag | Default | Meaning |
|---|---|---|
| `--output <file>` | standard output | Where to write the inventory |
| `--timeout <duration>` | `15m` | Give up if the whole run takes longer |
| `--max-memory <MB>` | `2048` | Stop above this much resident memory; `0` disables |
| `--max-files <n>` | from `--max-memory` | Skip any filesystem holding more files than this (524,288 at the default memory limit) |
| `--version` | | Print the version and exit |

Exit codes: `0` done, `1` an error, `2` time limit, `3` memory limit. On
`2` and `3` no inventory is written. Progress and the scope plan go to
standard error.

## Scan Scope (`scope.go`)

- `defaultScanPaths`: distro identification files, `/var/lib/dpkg`,
  `/var/lib/rpm`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt`,
  `/srv`, `/export`. Home directories are not walked.
- `localFSTypes`: an allowlist (ext2/3/4, xfs, btrfs, zfs, f2fs,
  bcachefs). Anything else, including NFS, autofs and tmpfs, is skipped
  and reported.
- `fileBudget`: syft holds a record of every file it walks in memory
  (roughly 4 KB each), so a filesystem with more files than the memory
  limit can afford is skipped and reported too. The count comes from one
  `statfs` call, with no walking. It applies to a wanted path on its own
  filesystem and to a filesystem mounted inside a walked path. It cannot
  apply to the root filesystem, whose count covers the whole machine, or
  to a filesystem that does not report a count (btrfs).
- Each wanted path is symlink-resolved first. Every sibling on the way to
  a wanted path, and every non-local mount inside one, becomes two syft
  exclude patterns: `./x` and `./x/**`. The second stops syft following a
  symlink into an excluded area.
- syft settings that differ from its defaults are commented in `scan.go`:
  binaries owned by OS packages are kept, installed-package catalogers
  are on, the kernel and ELF package-note catalogers are off, and no
  per-file records or "contains" relationships are produced.

## The Inventory

syft-json, plus one top-level key:

```
patchAgent
├─ agentVersion, syftVersion, collectedAt
├─ runningKernel, uptimeSeconds
├─ runSeconds, peakMemoryKB            cost of this run
├─ scope { walked[], skipped[{path, reason}] }
├─ listeners[]
│   ├─ protocol, address, port
│   ├─ netNamespace                    "host" or the kernel's name for another
│   └─ processes[]
│       ├─ pid, exe, exeDeleted, exeIsHostFile, sha256
│       ├─ unit, cwd, fileArgument
│       ├─ project { dir, manifest, name, version, gitRemote, gitCommit }
│       └─ problem
├─ apt                                 absent where there is no apt
│   ├─ listsUpdated
│   ├─ repos[{name, origin, label, suite, codename}]
│   └─ debs[{name, version, architecture, installedVersionIn[], listed[{repo, versions[]}]}]
└─ problems[]                          non-empty means the inventory is partial
```

Field meanings are documented on the structs in `sockets.go`,
`project.go`, `apt.go` and `extra.go`.

## Rules the Code Keeps

- **Read only.** Nothing is executed and nothing is written except the
  output file. Sockets, processes and mounts all come from `/proc`.
- **No free text.** No README or description is collected, and syft's
  `description`, `summary`, `title` and `comments` fields are stripped.
  Command lines are never reported; only the first argument that is an
  existing file is kept.
- **Files a user can plant are treated as hostile.** Project files are
  read through the process's own root (`os.OpenRoot`), must be regular
  files (a symlink, pipe or device is refused), are capped at 256 KB, and
  parse errors are never echoed. Credentials are removed from git remotes.
- **Paths inside a container are labelled.** `exeIsHostFile` is true only
  when the host's file at that path is the very file the process runs.
- **Gentle by default.** Nice 19 and idle I/O class on every thread,
  `oom_score_adj` 1000, and the two limits above.

## Testing

- Standard `testing`, one test file per source file, about 15 top-level
  tests with subtests.
- No real machine is needed: tests build pretend `/proc` trees, apt list
  directories and filesystems in temp dirs (`fakeProc`, `makeTree`,
  `writeLists` are the helpers to reuse).
- syft itself is not exercised by the unit tests. Its behaviour was
  checked by running the built agent on real machines.
- Run: `go test ./...`, plus `go vet ./...` and `govulncheck ./...`.
  `GOOS=linux go vet ./...` covers the Linux-only file from a Mac.

## Building and Running

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags='-s -w -X main.Version=<version>' -o patch-agent .

sudo ./patch-agent --output inventory.json
```

Root is needed to see other users' sockets and program files. The agent
only runs on Linux. For a kernel-enforced memory cap on a shared machine,
wrap it:

```
sudo systemd-run --scope -q -p MemoryMax=2G -p MemorySwapMax=0 \
  -p CPUWeight=20 -p IOWeight=20 nice -n 19 ionice -c3 \
  ./patch-agent --output inventory.json
```

## Not Built Yet

Posting to a central service, enrolment and identity, a config file to
add or skip paths, scanning a very large software area in pieces, home
directories, the contents of containers, the app folder
and loaded libraries of listening processes, packaging and signing, stage
two (applying fixes).

## Where the Reasoning Lives

`ant foundation` says what the project is for. `ant handover` says where
work stopped and lists every note in reading order. The notes this code
follows most directly:

| Topic | Note |
|---|---|
| Why syft, the syft settings, Grype as the central matcher | `pa-sYVTv`, `pa-sXVTv` |
| The scan, its scope, self-limits, and how syft behaves | `pa-mYBCN` |
| What Grype makes of an inventory | `pa-ZP9vQ` |
| Listening sockets, project identity, no free text | `pa-heCEJ` |
| Symlinks leaving the scope; results on a lived-in machine | `pa-bREz9` |
| Deb origin facts and the rule they feed | `pa-UYWmj`, `pa-uqwCr` |

What the central service must do with an inventory is listed in the
back-end project's notebook (`../patch-agent-backend`, note `pab-AkRXV`),
with sample inventories in that project's `samples/` folder.
