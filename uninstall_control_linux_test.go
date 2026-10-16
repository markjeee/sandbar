//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"strings"
	"testing"
)

func TestUninstallLinuxEmptyShortControlDirectory(t *testing.T) {
	p, _, _, _ := linuxUninstallFixture(t)
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	ownerUID, err := uninstallSudoOwner(account.Uid, account.Username)
	if os.Getuid() == 0 {
		ownerUID = os.Getuid() // The fixture also supports root-owned temporary installations.
	} else if err != nil {
		t.Fatal(err)
	}
	root := teleportShortControlDir(p, ownerUID)
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	plan, err := buildUninstallPlan(p, ownerUID, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var preview bytes.Buffer
	printUninstallPlan(plan, &preview)
	if !strings.Contains(preview.String(), "Remove when empty: "+root) || len(plan.Config.Teleports) != 0 {
		t.Fatal(preview.String(), plan.Config.Teleports)
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatal("preview changed the short control directory", err)
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
	p.installed.GroupID = -1
	repeated, err := buildUninstallPlan(p, ownerUID, io.Discard)
	if err != nil || !repeated.AlreadyRemoved {
		t.Fatal("repeat did not recognize completed cleanup", repeated, err)
	}
	for _, path := range []string{root, p.state} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("repeat recreated removed state", path, err)
		}
	}
}
