package main

import (
	"errors"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
)

// Discovery keeps service observations independent from package layout checks.
func doctorInstallation() (*installation, error) {
	if runtime.GOARCH != "arm64" || os.Geteuid() == 0 {
		return nil, errors.New("installed diagnostics require macOS arm64 and the current non-root user")
	}
	if err := checkHomebrewEnvironmentOverride(); err != nil {
		return nil, err
	}
	brew, err := exec.LookPath("brew")
	if err != nil {
		return nil, err
	}
	prefix, err := brewOutput(brew, "--prefix")
	if err != nil {
		return nil, err
	}
	metadata, err := brewOutput(brew, "info", "--json=v2", "caddy")
	if err != nil {
		return nil, err
	}
	account, err := user.Current()
	if err != nil {
		return nil, err
	}
	i, err := homebrewInstallation(strings.TrimSpace(string(prefix)), metadata, account)
	if err != nil {
		return nil, err
	}
	i.Service = &homebrewService{brew: brew, installation: i}
	return recordedDarwinInstallation(i, brew)
}
