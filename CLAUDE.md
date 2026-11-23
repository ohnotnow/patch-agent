# patch-agent

A prototype agent that runs as root on a Linux machine, records what is
installed and what is listening, and writes one JSON inventory for a
central service to judge. It observes and reports; it does not match
vulnerabilities and changes nothing on the machine.

This file is deliberately short. The detail lives in three places, and
they are the ones to keep current:

1. `ant foundation`: what the project is for and what it is not.
2. `ant handover`: where work stopped, what is agreed, what is undecided,
   and every note in reading order. Read the notes it lists before
   designing anything.
3. `TECHNICAL_OVERVIEW.md`: how the code works as it stands.

The central service is a separate project, `../patch-agent-backend`. Its
notebook holds the list of what must be done to an inventory there, and
its `samples/` folder holds sample inventories and Grype results.

## Build and test

```
go test ./... && go vet ./... && GOOS=linux go vet ./...
govulncheck ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o patch-agent .
```

The agent only runs on Linux, as root. Test machines and how to reach
them are described in the handover.

## Two things to be careful about

- **Real machines' details stay out of everything.** Inventories contain
  addresses, paths, user names and project names. Never print them into a
  conversation, a note, a test or a commit; report counts. Test data uses
  documentation addresses (`192.0.2.x`) and `example.com`.
- **Be gentle on machines that are doing real work.** The agent limits
  itself, but on anything shared or precious also use the capped
  `systemd-run` command in `TECHNICAL_OVERVIEW.md`, and check afterwards
  that nothing else was disturbed.
