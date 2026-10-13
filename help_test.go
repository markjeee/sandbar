package main

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestHelpMatchesNativePlatform(t *testing.T) {
	commands := map[string][]string{
		"setup":  {"--user", "--migrate-config", "systemd"},
		"reload": {"/etc/sandbar/config.json"},
		"status": {"boot startup"},
		"start":  {"caddy.service", "journalctl"},
		"stop":   {"does not disable Caddy's boot startup"},
		"trust":  {"/var/lib/sandbar/root.crt"},
	}
	if runtime.GOOS == "darwin" {
		commands = map[string][]string{
			"setup":  {"current user's Homebrew Caddy service", "sandbar setup --check", "registers login startup"},
			"reload": {"~/Library/Application Support/sandbar/config.json"},
			"status": {"login startup"},
			"start":  {"registers login startup", "<Homebrew prefix>/var/log/caddy.log"},
			"stop":   {"unregisters login startup"},
			"trust":  {"~/Library/Application Support/sandbar/state/root.crt"},
		}
	}
	for command, want := range commands {
		text, ok := helpText(command)
		if !ok {
			t.Fatalf("missing %s help", command)
		}
		for _, phrase := range want {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s help missing %q", command, phrase)
			}
		}
		if runtime.GOOS == "darwin" {
			for _, phrase := range []string{"--user", "--migrate-config", "--migrate-state", "systemd", "journalctl", "boot startup"} {
				if strings.Contains(text, phrase) {
					t.Errorf("macOS %s help contains Linux instruction %q", command, phrase)
				}
			}
		}
	}
}
