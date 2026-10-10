//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandHelpBeforeSideEffects(t *testing.T) {
	calls := fakeCaddy(t)
	home := filepath.Join(shortHome(t), "not-created")
	for _, command := range []string{"setup", "init", "add", "rm", "ls", "reload", "status", "start", "stop", "trust", "untrust"} {
		for _, option := range []string{"--help", "-h"} {
			code, out, errOut := cli(t, "--home", home, command, option)
			if code != 0 || errOut != "" || !strings.Contains(out, "Usage: sandbar "+command) || !strings.Contains(out, "Example:") && !strings.Contains(out, "Example: ") {
				t.Fatalf("%s %s: exit %d, output %q, error %q", command, option, code, out, errOut)
			}
		}
	}
	for _, path := range []string{home, calls} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("help caused work at %s: %v", path, err)
		}
	}
}

func TestHelpDoesNotRequireValidPaths(t *testing.T) {
	t.Setenv("SANDBAR_HOME", "invalid\npath")
	t.Setenv("PATH", t.TempDir())
	for _, args := range [][]string{nil, {"--help"}, {"help"}, {"status", "--help"}, {"setup", "--help"}} {
		code, out, errOut := cli(t, args...)
		if code != 0 || out == "" || errOut != "" {
			t.Fatalf("%v: %d %q %q", args, code, out, errOut)
		}
	}
}

func TestHelpRequestStopsAtArgumentSeparator(t *testing.T) {
	if commandHelpRequested([]string{"--", "--help"}) {
		t.Fatal("positional --help treated as a help option")
	}
	if !commandHelpRequested([]string{"--replace", "--help"}) {
		t.Fatal("help option not found")
	}
}
