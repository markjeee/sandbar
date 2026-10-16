package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDarwinUninstallEmptyShortControlDirectory(t *testing.T) {
	p, service, _ := uninstallDarwinFixture(t)
	root := teleportShortControlDir(p, os.Getuid())
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	evidence := uninstallEvidence(t, p)
	plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var preview bytes.Buffer
	printUninstallPlan(plan, &preview)
	if !strings.Contains(preview.String(), "Remove when empty: "+root) || len(plan.Config.Teleports) != 0 {
		t.Fatal(preview.String(), plan.Config.Teleports)
	}
	assertUninstallEvidence(t, evidence)
	if len(service.Actions) != 0 {
		t.Fatal("preview changed the service", service.Actions)
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("preview changed the short control directory", info, err)
	}
	if err := runUninstallUser(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := finishUninstall(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("retained the empty short control directory", err)
	}
	old := launchdOutput
	launchdOutput = func(string, ...string) ([]byte, error) {
		err := exec.Command("/bin/sh", "-c", "exit 113").Run()
		return nil, fmt.Errorf("Could not find service \"%s\" in domain for user gui: %w", sandbarLaunchdLabel, err)
	}
	t.Cleanup(func() { launchdOutput = old })
	repeated, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil || !repeated.AlreadyRemoved {
		t.Fatal("repeat did not recognize completed cleanup", repeated, err)
	}
	for _, path := range []string{root, p.state} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("repeat recreated removed state", path, err)
		}
	}
}

func TestDarwinUninstallPreviewDoesNotCreateShortControlDirectory(t *testing.T) {
	p, _, _ := uninstallDarwinFixture(t)
	root := teleportShortControlDir(p, os.Getuid())
	plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var preview bytes.Buffer
	printUninstallPlan(plan, &preview)
	if strings.Contains(preview.String(), root) {
		t.Fatal("preview included a missing directory", preview.String())
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview created a short control directory", err)
	}
}

func TestDarwinUninstallShortControlDirectoryConflicts(t *testing.T) {
	for _, conflict := range []string{"unknown file", "unregistered socket", "symlink", "permissions"} {
		t.Run(conflict, func(t *testing.T) {
			p, service, calls := uninstallDarwinFixture(t)
			root := teleportShortControlDir(p, os.Getuid())
			if conflict == "symlink" {
				if err := os.Symlink(t.TempDir(), root); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			switch conflict {
			case "unknown file":
				if err := os.WriteFile(root+"/unknown", []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unregistered socket":
				listener, err := net.Listen("unix", root+"/unknown.sock")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			case "permissions":
				if err := os.Chmod(root, 0755); err != nil {
					t.Fatal(err)
				}
			}
			evidence := uninstallEvidence(t, p)
			if _, err := buildUninstallPlan(p, os.Getuid(), io.Discard); err == nil {
				t.Fatal("accepted control directory conflict", conflict)
			}
			assertUninstallEvidence(t, evidence)
			if len(service.Actions) != 0 {
				t.Fatal("conflict changed the service", service.Actions)
			}
			for _, call := range readCalls(t, calls) {
				if call[0] != "version" && call[0] != "adapt" {
					t.Fatal("preflight invoked a mutating command", call)
				}
			}
			if _, err := os.Lstat(root); err != nil {
				t.Fatal("removed conflicting control directory", err)
			}
		})
	}
}
