//go:build !linux

package main

// stayOutOfTheWay does nothing off Linux. The agent only runs on Linux; this
// exists so the tests build on a developer's machine.
func stayOutOfTheWay() []string { return nil }
