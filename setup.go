package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type setupRecord struct {
	Identity string        `json:"identity"`
	Manifest inputManifest `json:"manifest"`
}

func readSetupRecord(p paths) (setupRecord, error) {
	var record setupRecord
	data, err := os.ReadFile(p.file("setup.json"))
	if err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, err
	}
	return record, nil
}

type setupBackup struct {
	Path      string      `json:"path"`
	Data      []byte      `json:"data"`
	Mode      os.FileMode `json:"mode"`
	UID, GID  int
	Published []byte `json:"published"`
}
type setupUndo struct {
	Files         []setupBackup
	Directories   []setupDirectoryBackup
	Expected      []setupSnapshot `json:"-"`
	Dir           string
	Prior         serviceState
	LegacyRestart string
}

func (u *setupUndo) save() error {
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteMode(filepath.Join(u.Dir, "backup.json"), append(data, '\n'), 0600, -1, -1)
}
func (u *setupUndo) write(path string, data []byte, mode os.FileMode, uid, gid int) error {
	for _, snapshot := range u.Expected {
		if snapshot.Path == path {
			if err := checkSetupSnapshots([]setupSnapshot{snapshot}); err != nil {
				return err
			}
		}
	}
	var entry setupBackup
	entry.Path = path
	entry.Published = data
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("setup refuses non-regular file: %s", path)
		}
		entry.Data, err = os.ReadFile(path)
		if err != nil {
			return err
		}
		entry.Mode = info.Mode() & (os.ModePerm | os.ModeSetgid | os.ModeSetuid | os.ModeSticky)
		stat := info.Sys().(*syscall.Stat_t)
		entry.UID, entry.GID = int(stat.Uid), int(stat.Gid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	u.Files = append(u.Files, entry)
	if err := u.save(); err != nil {
		return err
	}
	return atomicWriteMode(path, data, mode, uid, gid)
}
func (u *setupUndo) restore() error {
	var failures []error
	for n := len(u.Files) - 1; n >= 0; n-- {
		file := u.Files[n]
		current, err := readOptional(file.Path)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if sameFileBytes(current, file.Data) {
			continue
		}
		if !sameFileBytes(current, file.Published) {
			failures = append(failures, fmt.Errorf("external edit preserved at %s", file.Path))
			continue
		}
		if file.Data == nil {
			err = os.Remove(file.Path)
		} else {
			err = atomicWriteMode(file.Path, file.Data, file.Mode, file.UID, file.GID)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	for n := len(u.Directories) - 1; n >= 0; n-- {
		dir := u.Directories[n]
		if dir.Created {
			continue
		}
		info, err := os.Lstat(dir.Path)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		stat := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || fileAccessMode(info.Mode()) != dir.PublishedMode || int(stat.Uid) != dir.PublishedUID || int(stat.Gid) != dir.PublishedGID {
			failures = append(failures, fmt.Errorf("external directory edit preserved: %s", dir.Path))
			continue
		}
		if err := os.Chown(dir.Path, dir.UID, dir.GID); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := os.Chmod(dir.Path, dir.Mode); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
func setupDirectory(path string, mode os.FileMode, uid, gid int) error {
	info, err := os.Lstat(path)
	if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return fmt.Errorf("setup refuses directory symlink or other file: %s", path)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
func exportServiceRoot(p paths, undo *setupUndo) error {
	path := filepath.Join(p.installed.Storage, "pki/authorities/sandbar/root.crt")
	var data []byte
	var err error
	for attempt := 0; attempt < 30; attempt++ {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("read service CA: %w", err)
	}
	return undo.write(p.rootCertificate(), data, installedRootMode, installedRootUID, installedRootUID)
}
func verifySetupRoutes(p paths, c config) error {
	roots, err := selectedStatusRoots(p.rootCertificate())
	if err != nil {
		return err
	}
	for _, r := range append([]route{{Hostname: "sandbar.localhost"}}, c.Routes...) {
		code, err := waitForSetupCertificate(func() (int, error) { return checkHTTPSRoute(c, r, roots) }, 3*time.Second)
		if err != nil {
			return fmt.Errorf("verify setup route %s: %w", r.Hostname, err)
		}
		if code >= 500 {
			return fmt.Errorf("setup route %s returned HTTP %d", r.Hostname, code)
		}
		if err := verifySetupRedirect(c, r.Hostname); err != nil {
			return err
		}
	}
	return nil
}

func captureSetupInputs(manifest inputManifest, i *installation) (inputManifest, error) {
	result := inputManifest{Globs: manifest.Globs}
	for _, file := range manifest.Files {
		if file.Path == i.Globals {
			continue
		}
		if file.Path == i.Config {
			data, err := os.ReadFile(file.Path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return result, err
			}
			hash := sha256.Sum256(data)
			file.SHA256 = hex.EncodeToString(hash[:])
		}
		result.Files = append(result.Files, file)
	}
	return result, nil
}

func verifySetupRedirect(c config, hostname string) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.HTTPPort)))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: routeCheckTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest(http.MethodHead, "http://"+net.JoinHostPort(hostname, strconv.Itoa(c.HTTPPort))+"/", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("verify HTTP redirect for %s: %w", hostname, err)
	}
	defer response.Body.Close()
	if response.StatusCode != 308 || response.Header.Get("Location") != c.routeURL(hostname)+"/" {
		return fmt.Errorf("unexpected HTTP redirect for %s: HTTP %d", hostname, response.StatusCode)
	}
	return nil
}

type setupSnapshot struct {
	Path string
	Data []byte
}

func checkSetupSnapshots(snapshots []setupSnapshot) error {
	for _, snapshot := range snapshots {
		info, err := os.Lstat(snapshot.Path)
		if err == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("setup refuses non-regular input: %s", snapshot.Path)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		data, err := readOptional(snapshot.Path)
		if err != nil {
			return err
		}
		if !sameFileBytes(data, snapshot.Data) {
			return fmt.Errorf("file changed during setup: %s; retry setup --check", snapshot.Path)
		}
	}
	return nil
}
func fileAccessMode(mode os.FileMode) os.FileMode {
	return mode & (os.ModePerm | os.ModeSetgid | os.ModeSetuid | os.ModeSticky)
}

type setupDirectoryBackup struct {
	Path                       string
	Mode                       os.FileMode
	UID, GID                   int
	Created                    bool
	PublishedMode              os.FileMode
	PublishedUID, PublishedGID int
}

func (u *setupUndo) directory(path string, mode os.FileMode, uid, gid int) error {
	entry := setupDirectoryBackup{Path: path, PublishedMode: mode, PublishedUID: uid, PublishedGID: gid}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		entry.Created = true
	} else if err != nil {
		return err
	} else {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("setup refuses directory input: %s", path)
		}
		stat := info.Sys().(*syscall.Stat_t)
		entry.Mode = fileAccessMode(info.Mode())
		entry.UID, entry.GID = int(stat.Uid), int(stat.Gid)
	}
	u.Directories = append(u.Directories, entry)
	if err := u.save(); err != nil {
		return err
	}
	return setupDirectory(path, mode, uid, gid)
}

// Native acceptance observed leaf issuance after systemd reported readiness.
// Wait only for Caddy's initial TLS internal alert. Other TLS and app errors fail immediately.
func waitForSetupCertificate(check func() (int, error), limit time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	for {
		code, err := check()
		if err == nil {
			return code, nil
		}
		var tlsErr *routeTLSError
		var remote *net.OpError
		if !errors.As(err, &tlsErr) || !errors.As(tlsErr, &remote) || remote.Op != "remote error" || remote.Err.Error() != "tls: internal error" {
			return 0, err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return 0, fmt.Errorf("initial HTTPS certificate was not ready within %s: %w", limit, err)
		case <-timer.C:
		}
	}
}
