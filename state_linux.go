package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type paths struct {
	config    string
	state     string
	installed *installation
}

func resolvePaths(home string) (paths, error) {
	var configDir, stateDir string
	if home != "" {
		configDir, stateDir = home, filepath.Join(home, "state")
	} else {
		i, err := inspectInstallation()
		if err != nil {
			return paths{}, err
		}
		return installedPaths(i), nil
	}
	configDir, err := filepath.Abs(configDir)
	if err != nil {
		return paths{}, err
	}
	stateDir, err = filepath.Abs(stateDir)
	if err != nil {
		return paths{}, err
	}
	return paths{config: filepath.Join(configDir, "config.json"), state: stateDir}, nil
}

func (p paths) file(name string) string {
	if p.installed != nil {
		switch name {
		case "Caddyfile":
			return filepath.Join(p.state, "routes/Caddyfile")
		case "admin.sock":
			return filepath.Join(p.state, "admin/admin.sock")
		case "router.lock":
			return filepath.Join(p.state, "work/router.lock")
		}
		if name == "transaction" || strings.HasPrefix(name, "transaction/") || name == "transaction-complete" {
			return filepath.Join(p.state, "work", name)
		}
	}
	return filepath.Join(p.state, name)
}
func (p paths) workDir() string {
	if p.installed != nil {
		return p.file("work")
	}
	return p.state
}
func (p paths) adminAddress() (string, error) {
	socket := p.file("admin.sock")
	// Linux sockaddr_un.sun_path has 108 bytes, including the terminator.
	if len(socket) > 107 {
		return "", fmt.Errorf("admin socket path is too long; use --home with a shorter path: %s", socket)
	}
	if strings.ContainsAny(socket, "{}|") {
		return "", fmt.Errorf("admin socket path contains Caddy syntax; use --home without braces or vertical bars")
	}
	for _, ch := range socket {
		if ch < 32 || ch == 127 {
			return "", fmt.Errorf("admin socket path contains a control character")
		}
	}
	return "unix/" + socket, nil
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

func withLock(p paths, action func() error) error {
	if p.installed == nil {
		for _, dir := range []string{filepath.Dir(p.config), p.state} {
			if err := privateDir(dir); err != nil {
				return fmt.Errorf("prepare private directory: %w", err)
			}
		}
	} else if err := p.requireSetup(); err != nil {
		return err
	}
	mode := os.FileMode(0600)
	if p.installed != nil {
		mode = 0660
	}
	file, err := os.OpenFile(p.file("router.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return fmt.Errorf("open router lock: %w", err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock router: %w", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return action()
}
