package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type paths struct {
	config string
	state  string
}

func resolvePaths(home string) (paths, error) {
	var configDir, stateDir string
	if home != "" {
		configDir, stateDir = home, filepath.Join(home, "state")
	} else {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return paths{}, err
		}
		configDir = os.Getenv("XDG_CONFIG_HOME")
		if !filepath.IsAbs(configDir) {
			configDir = filepath.Join(userHome, ".config")
		}
		stateDir = os.Getenv("XDG_STATE_HOME")
		if !filepath.IsAbs(stateDir) {
			stateDir = filepath.Join(userHome, ".local", "state")
		}
		configDir = filepath.Join(configDir, "sandbar")
		stateDir = filepath.Join(stateDir, "sandbar")
	}
	configDir, err := filepath.Abs(configDir)
	if err != nil {
		return paths{}, err
	}
	stateDir, err = filepath.Abs(stateDir)
	if err != nil {
		return paths{}, err
	}
	return paths{filepath.Join(configDir, "config.json"), stateDir}, nil
}

func (p paths) file(name string) string { return filepath.Join(p.state, name) }
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
	for _, dir := range []string{filepath.Dir(p.config), p.state} {
		if err := privateDir(dir); err != nil {
			return fmt.Errorf("prepare private directory: %w", err)
		}
	}
	file, err := os.OpenFile(p.file("router.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
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
