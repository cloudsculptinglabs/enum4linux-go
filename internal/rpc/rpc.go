// Package rpc enumerates users, groups, and the password policy over MS-RPC.
//
// enum4linux drove these through Samba's `rpcclient`. Native SAMR/LSA over
// SMB is on the roadmap; for now this shells out to rpcclient when present so
// the feature works today, and returns a clear error when it is not installed.
package rpc

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// available reports whether rpcclient is on PATH.
func available() bool {
	_, err := exec.LookPath("rpcclient")
	return err == nil
}

func run(host, user, pass, command string, timeout time.Duration) (string, error) {
	if !available() {
		return "", fmt.Errorf("rpcclient not found on PATH (native SAMR is a TODO)")
	}
	auth := fmt.Sprintf("%s%%%s", user, pass) // empty%%empty = null session
	cmd := exec.Command("rpcclient", "-U", auth, "-c", command, host)
	// A hard ceiling so a hung RPC call cannot stall the run.
	timer := time.AfterFunc(timeout, func() { _ = cmd.Process.Kill() })
	out, err := cmd.CombinedOutput()
	timer.Stop()
	if err != nil {
		return string(out), fmt.Errorf("rpcclient %q: %w", command, err)
	}
	return string(out), nil
}

// Users enumerates domain users (rpcclient enumdomusers).
func Users(host, user, pass string, timeout time.Duration) ([]string, error) {
	out, err := run(host, user, pass, "enumdomusers", timeout)
	if err != nil {
		return nil, err
	}
	return parseNames(out), nil
}

// Groups enumerates domain groups (rpcclient enumdomgroups).
func Groups(host, user, pass string, timeout time.Duration) ([]string, error) {
	out, err := run(host, user, pass, "enumdomgroups", timeout)
	if err != nil {
		return nil, err
	}
	return parseNames(out), nil
}

// PasswordPolicy returns the raw domain password policy (rpcclient getdompwinfo).
func PasswordPolicy(host, user, pass string, timeout time.Duration) (string, error) {
	out, err := run(host, user, pass, "getdompwinfo", timeout)
	return strings.TrimSpace(out), err
}

// parseNames extracts the bracketed names from rpcclient enum* output lines
// like: user:[alice] rid:[0x3e8]
func parseNames(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		start := strings.Index(line, "[")
		end := strings.Index(line, "]")
		if start >= 0 && end > start {
			names = append(names, line[start+1:end])
		}
	}
	return names
}
