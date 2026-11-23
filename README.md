# patch-agent

> **Work in progress. This is an early prototype, not a finished tool.**
> It changes often, has had little real-world use, and its output format
> and behaviour are not stable. Please don't run it on machines you care
> about or build anything on top of it.

patch-agent runs as root on a Linux machine and writes one JSON inventory
of what is installed and what is listening on the network. It does no
vulnerability matching, changes nothing on the machine, and never runs a
program to find out what it is. Matching and ranking are meant to happen
in a separate central service.

The inventory is [syft](https://github.com/anchore/syft)'s JSON format plus
a `patchAgent` section covering the listening processes and where apt
thinks each installed deb came from.

## Building

Needs Go 1.27.4 or later.

```
git clone https://github.com/ohnotnow/patch-agent.git
cd patch-agent
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o patch-agent .
```

Use `GOARCH=arm64` for 64-bit ARM machines.

## Running

Linux only, as root:

```
sudo ./patch-agent --output inventory.json
```

It lowers its own CPU and disk priority and stops if it goes over
`--max-memory` (2048 MB by default) or `--timeout` (15 minutes). See
[TECHNICAL_OVERVIEW.md](TECHNICAL_OVERVIEW.md) for the flags, exit codes,
what gets scanned, and the inventory's layout.

## Licence

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See
[LICENSE](LICENSE).
