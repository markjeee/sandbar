package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallShortControlDirectoryUsesSelectedOwner(t *testing.T) {
	p := paths{config: filepath.Join(t.TempDir(), "config.json"), state: filepath.Join(t.TempDir(), strings.Repeat("state", 30))}
	ownerUID := os.Getuid() + 1
	root := teleportShortControlDir(p, ownerUID)
	socket, _, err := teleportControlPathsForOwner(p, teleportDestination{Machine: "peer"}, ownerUID)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(socket) != root || root == teleportShortControlDir(p, os.Getuid()) {
		t.Fatal("short control path did not use the selected owner", socket, root)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	plan := &uninstallPlan{Paths: p, OwnerUID: ownerUID}
	if err := plan.addTeleportControlDirectory(); err == nil {
		t.Fatal("accepted a directory owned by a different user")
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatal("changed a directory owned by a different user", err)
	}
}
