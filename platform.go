package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type serviceState struct {
	State      string
	Boot       string
	Diagnostic string
	Sockets    string
}

type serviceOperations interface {
	Inspect() (serviceState, error)
	Control(string, io.Writer, io.Writer) error
	Validate(io.Writer, io.Writer) error
}

type installation struct {
	ID       string            `json:"id"`
	Binary   string            `json:"binary"`
	Unit     string            `json:"unit"`
	Fragment string            `json:"fragment"`
	Config   string            `json:"config"`
	Globals  string            `json:"globals"`
	Source   string            `json:"source"`
	State    string            `json:"state"`
	Storage  string            `json:"storage"`
	Account  string            `json:"account"`
	UID      int               `json:"uid"`
	GID      int               `json:"gid"`
	CLI      string            `json:"cli,omitempty"`
	Log      string            `json:"log,omitempty"`
	GroupID  int               `json:"group_id"`
	Service  serviceOperations `json:"-"`
}

func (i installation) identity() string {
	data, _ := json.Marshal(i)
	return string(data)
}

func runBounded(binary string, env []string, in io.Reader, out, errOut io.Writer, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = env
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = errOut
	err := cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("command timed out; service state is unknown: %w", ctx.Err())
	}
	return err
}

func installedPaths(i *installation) paths {
	return paths{config: i.Source, state: i.State, installed: i}
}
func (p paths) rootCertificate() string {
	if p.installed != nil {
		return installedRootCertificate(p.installed)
	}
	return p.file("caddy/pki/authorities/local/root.crt")
}
func (p paths) caID() string {
	if p.installed != nil {
		return "sandbar"
	}
	return "local"
}
func (p paths) generatedPath() string { return p.file("Caddyfile") }
func (p paths) requireSetup() error {
	if p.installed == nil {
		return nil
	}
	data, err := os.ReadFile(p.file("setup.json"))
	if err != nil {
		return fmt.Errorf("service setup for Sandbar is missing or inaccessible; run %s: %w", setupCommand, err)
	}
	var record setupRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("invalid setup record: %w", err)
	}
	if record.Identity != p.installed.identity() {
		return fmt.Errorf("the Caddy installation differs from setup; review %s --check", setupCommand)
	}
	return nil
}

func (p paths) writeFile(path string, data []byte) error {
	mode := os.FileMode(0600)
	if p.installed != nil {
		mode = installedFileMode
	}
	return atomicWriteMode(path, data, mode, -1, -1)
}
func atomicWriteMode(path string, data []byte, mode os.FileMode, uid, gid int) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".sandbar-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := file.Chown(uid, gid); err != nil {
			file.Close()
			return err
		}
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func createSelectedConfig(p paths, c config) error {
	if p.installed == nil {
		return writeConfig(p.config, c)
	}
	data, err := configBytes(c)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(p.config, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, installedFileMode)
	if err != nil {
		return fmt.Errorf("create shared configuration: %w", err)
	}
	if err := file.Chmod(installedFileMode); err != nil {
		file.Close()
		return err
	}
	if err := file.Chown(-1, p.installed.GroupID); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p.config))
}
