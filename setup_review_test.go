package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetupRecoveryRefusesEveryExistingEntry(t *testing.T) {
	for _, kind := range []string{"directory", "malformed", "unreadable", "dangling symlink"} {
		t.Run(kind, func(t *testing.T) {
			p := paths{state: t.TempDir()}
			path := p.file("transaction")
			var err error
			switch kind {
			case "directory", "unreadable":
				err = os.Mkdir(path, 0700)
				if err == nil && kind == "unreadable" {
					err = os.Chmod(path, 0000)
					t.Cleanup(func() { _ = os.Chmod(path, 0700) })
				}
			case "malformed":
				err = os.WriteFile(path, []byte("invalid journal"), 0600)
			case "dangling symlink":
				err = os.Symlink(filepath.Join(p.state, "missing"), path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := checkSetupRecovery(p); err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("pending entry did not block setup: %v", err)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("guard removed transaction", err)
			}
		})
	}
	p := paths{state: filepath.Join(t.TempDir(), "missing")}
	if err := checkSetupRecovery(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p.state); !os.IsNotExist(err) {
		t.Fatal("guard created state", err)
	}
}

func TestSetupRollbackRestoresIdenticalContentMode(t *testing.T) {
	for _, originalMode := range []os.FileMode{0644, 0640 | os.ModeSetgid} {
		t.Run(originalMode.String(), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			data := []byte("unchanged")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, originalMode); err != nil {
				t.Fatal(err)
			}
			undo := setupUndo{Dir: dir}
			if err := undo.write(path, data, 0600, -1, -1); err != nil {
				t.Fatal(err)
			}
			if err := undo.restore(); err != nil {
				t.Fatal(err)
			}
			current, metadata, err := readSetupFile(path)
			if err != nil || !bytes.Equal(current, data) || metadata.Mode != originalMode || metadata.UID != os.Getuid() || metadata.GID != os.Getgid() {
				t.Fatal(string(current), metadata, err)
			}
		})
	}
}

func TestSetupRollbackRecordsEffectiveInheritedGroup(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	group := -1
	for _, candidate := range groups {
		if candidate != os.Getgid() {
			group = candidate
			break
		}
	}
	if group < 0 {
		t.Skip("changing file group requires a second caller group")
	}
	dir := t.TempDir()
	if err := os.Chown(dir, -1, os.Getgid()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	data := []byte("unchanged")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, -1, group); err != nil {
		t.Fatal(err)
	}
	undo := setupUndo{Dir: dir}
	if err := undo.write(path, data, 0640, -1, -1); err != nil {
		t.Fatal(err)
	}
	if undo.Files[0].PublishedMetadata.GID != os.Getgid() {
		t.Fatal("did not record inherited group", undo.Files[0].PublishedMetadata)
	}
	if err := undo.restore(); err != nil {
		t.Fatal(err)
	}
	_, metadata, err := readSetupFile(path)
	if err != nil || metadata.GID != group || metadata.UID != os.Getuid() {
		t.Fatal(metadata, err)
	}
}

func TestSetupRollbackPreservesConflictingMetadata(t *testing.T) {
	for _, field := range []string{"mode", "uid", "gid", "unknown publication"} {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			if err := os.WriteFile(path, []byte("unchanged"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			undo := setupUndo{Dir: dir}
			if err := undo.write(path, []byte("unchanged"), 0600, -1, -1); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "mode":
				if err := os.Chmod(path, 0620); err != nil {
					t.Fatal(err)
				}
			case "uid":
				undo.Files[0].PublishedMetadata.UID++
			case "gid":
				undo.Files[0].PublishedMetadata.GID++
			case "unknown publication":
				// A failed atomic publication can leave replacement bytes without a confirmed metadata snapshot.
				undo.Files[0].PublishedMetadata = nil
			}
			before, metadataBefore, err := readSetupFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := undo.restore(); err == nil || !strings.Contains(err.Error(), "external edit preserved") {
				t.Fatal("rollback accepted conflicting metadata", err)
			}
			after, metadataAfter, err := readSetupFile(path)
			if err != nil || !bytes.Equal(before, after) || *metadataBefore != *metadataAfter {
				t.Fatal("rollback changed external edit", metadataBefore, metadataAfter, err)
			}
		})
	}
}

func TestSetupBackupOlderRecordsRemainReadable(t *testing.T) {
	var undo setupUndo
	data := []byte(`{"Files":[{"path":"/fixture/config","data":"b2xk","mode":420,"UID":501,"GID":20,"published":"bmV3"}],"Dir":"/fixture/backup","Prior":{"State":"inactive","Boot":"disabled"}}`)
	if err := json.Unmarshal(data, &undo); err != nil {
		t.Fatal(err)
	}
	if len(undo.Files) != 1 || string(undo.Files[0].Data) != "old" || string(undo.Files[0].Published) != "new" || undo.Files[0].PublishedMetadata != nil {
		t.Fatal(undo)
	}
}
