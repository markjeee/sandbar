package main

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigPathSelectionWithoutRuntime(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	environment := filepath.Join(t.TempDir(), "environment")
	explicit := filepath.Join(t.TempDir(), "explicit")
	t.Setenv("SANDBAR_HOME", environment)
	for _, home := range []string{environment, explicit} {
		args := []string{"config", "--path"}
		if home == explicit {
			args = append([]string{"--home", explicit}, args...)
		}
		code, out, errOut := cli(t, args...)
		if code != 0 || out != filepath.Join(home, "config.json")+"\n" || errOut != "" {
			t.Fatalf("%v: %d %q %q", args, code, out, errOut)
		}
		if _, err := os.Stat(home); !os.IsNotExist(err) {
			t.Fatalf("path inspection created %s: %v", home, err)
		}
	}
	code, out, errOut := cli(t, "--home", ".sandbox/absent", "config", "--path")
	absolute, err := filepath.Abs(".sandbox/absent/config.json")
	if err != nil || code != 0 || out != absolute+"\n" || errOut != "" {
		t.Fatalf("relative selection: %d %q %q %v", code, out, errOut, err)
	}
}

func TestConfigInstalledPathBeforeSetup(t *testing.T) {
	t.Setenv("SANDBAR_HOME", "")
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	want := "/etc/sandbar/config.json"
	if runtime.GOOS == "darwin" {
		account, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		want = filepath.Join(account.HomeDir, "Library/Application Support/sandbar/config.json")
	}
	code, out, errOut := cli(t, "config", "--path")
	if code != 0 || out != want+"\n" || errOut != "" {
		t.Fatalf("installed selection: %d %q %q", code, out, errOut)
	}
}

func TestConfigPrintPreservesSource(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config.json")
	data := []byte("  {invalid JSON\r\n\x00no newline")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	for _, option := range []string{"--path", "--print"} {
		code, out, errOut := cli(t, "--home", home, "config", option)
		if code != 0 || errOut != "" || option == "--print" && !bytes.Equal([]byte(out), data) {
			t.Fatalf("%s: %d %q %q", option, code, out, errOut)
		}
	}
	if !bytes.Equal(readTestFile(t, path), data) {
		t.Fatal("inspection changed source bytes")
	}
	for path, mode := range map[string]os.FileMode{home: 0750, path: 0640} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("inspection changed mode at %s: %v %v", path, info, err)
		}
	}
	entries, err := os.ReadDir(home)
	if err != nil || len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatalf("inspection changed entries: %v %v", entries, err)
	}
}

func TestConfigPrintErrorsAndUsage(t *testing.T) {
	home := filepath.Join(t.TempDir(), "missing")
	path := filepath.Join(home, "config.json")
	code, out, errOut := cli(t, "--home", home, "config", "--print")
	if code == 0 || out != "" || !strings.Contains(errOut, path) {
		t.Fatalf("missing source: %d %q %q", code, out, errOut)
	}
	for _, args := range [][]string{nil, {"--path", "--print"}, {"--path", "extra"}, {"--unsupported"}} {
		code, out, _ := cli(t, append([]string{"--home", home, "config"}, args...)...)
		if code == 0 || out != "" {
			t.Fatalf("usage %v: %d %q", args, code, out)
		}
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("failed inspection created home: %v", err)
	}
}

func TestConfigUnreadableSource(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode 0000 files")
	}
	home := t.TempDir()
	path := filepath.Join(home, "config.json")
	if err := os.WriteFile(path, []byte("private"), 0000); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := cli(t, "--home", home, "config", "--print")
	if code == 0 || out != "" || !strings.Contains(errOut, path) || !strings.Contains(errOut, "permission denied") {
		t.Fatalf("unreadable source: %d %q %q", code, out, errOut)
	}
}

func TestSelectedCommandContext(t *testing.T) {
	p := paths{config: "/tmp/developer's home/config.json"}
	if got := selectedCommand(p, "teleport", "connect", "remote"); got != `sandbar --home '/tmp/developer'\''s home' teleport connect remote` {
		t.Fatal(got)
	}
	p.installed = &installation{}
	if got := selectedCommand(p, "teleport", "connect", "remote"); got != "sandbar teleport connect remote" {
		t.Fatal(got)
	}
}
