package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func invokeSelectedCaddy(p paths, env []string, in io.Reader, out, errOut io.Writer, args ...string) error {
	if p.installed == nil {
		return invokeCaddy(env, in, out, errOut, args...)
	}
	if err := runBounded(p.installed.Binary, env, in, out, errOut, args...); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() > 0 {
			return &caddyError{exit.ExitCode(), fmt.Errorf("caddy %s: %w", args[0], err)}
		}
		return fmt.Errorf("caddy %s: %w", args[0], err)
	}
	return nil
}
func checkSelectedCaddy(p paths, env []string, errOut io.Writer) error {
	if p.installed == nil {
		return checkCaddy(env, errOut)
	}
	var out bytes.Buffer
	if err := invokeSelectedCaddy(p, env, nil, &out, errOut, "version"); err != nil {
		return err
	}
	return checkCaddyVersion(out.String())
}

func installedCandidate(p paths, routeBytes []byte, c config, out, errOut io.Writer) ([]byte, error) {
	if err := checkAcceptedInputs(p); err != nil {
		return nil, err
	}
	candidate, _, err := stageInstalledCandidate(p.installed.Config, p.installed.Globals, p.generatedPath(), routeBytes)
	if err != nil {
		return nil, err
	}
	path := p.file("validation/Caddyfile")
	if err := p.writeFile(path, candidate); err != nil {
		return nil, err
	}
	adapted, err := adaptCaddyfile(p, path, errOut)
	if err != nil {
		return nil, err
	}
	address, err := p.adminAddress()
	if err != nil {
		return nil, err
	}
	if err := checkInstalledAdapted(adapted, c, address); err != nil {
		return nil, err
	}
	if err := p.installed.Service.Validate(out, errOut); err != nil {
		return nil, err
	}
	if err := checkAcceptedInputs(p); err != nil {
		return nil, err
	}
	return adapted, nil
}
func checkAcceptedInputs(p paths) error {
	if p.installed == nil {
		return nil
	}
	record, err := readSetupRecord(p)
	if err != nil {
		return err
	}
	if record.Identity != p.installed.identity() {
		return errors.New("the Caddy installation differs from setup; review setup before changing routes")
	}
	if err := verifyInputManifest(record.Manifest); err != nil {
		return fmt.Errorf("the Caddy configuration changed; review %s --check: %w", setupCommand, err)
	}
	return nil
}
func committedAdaptedConfig(p paths, errOut io.Writer) ([]byte, error) {
	if p.installed == nil {
		return adaptCaddyfile(p, p.generatedPath(), errOut)
	}
	if err := checkAcceptedInputs(p); err != nil {
		return nil, err
	}
	return adaptCaddyfile(p, p.installed.Config, errOut)
}

func selectedActiveConfig(p paths) ([]byte, error) {
	if p.installed == nil {
		return readActiveConfig(p)
	}
	state, stateErr := p.installed.Service.Inspect()
	active, adminErr := readActiveConfig(p)
	if adminErr == nil {
		return active, nil
	}
	if stateErr != nil {
		return nil, fmt.Errorf("cannot establish Caddy service and admin state: %v; %v", stateErr, adminErr)
	}
	if state.State == "inactive" && isRouterStopped(adminErr) {
		return nil, syscall.ENOENT
	}
	return nil, fmt.Errorf("cannot establish active Caddy configuration (service %s): %v", state.State, adminErr)
}

func startInstalled(p paths, out, errOut io.Writer) error {
	if err := recoverTransaction(p, errOut); err != nil {
		return err
	}
	state, err := p.installed.Service.Inspect()
	if err != nil {
		return err
	}
	if state.State == "active" {
		c, err := readConfig(p.config)
		if err != nil {
			return err
		}
		active, err := readActiveConfig(p)
		if err != nil {
			return err
		}
		if registerLoginStartup && state.Boot != "enabled" {
			if err := configurationStatus(c, p, active, nil, out, errOut); err != nil {
				return err
			}
			generated, err := os.ReadFile(p.generatedPath())
			if err != nil {
				return err
			}
			if _, err := installedCandidate(p, generated, c, out, errOut); err != nil {
				return err
			}
			if err := p.installed.Service.Control("start", out, errOut); err != nil {
				return fmt.Errorf("register Caddy login startup: %w", err)
			}
			fmt.Fprintln(out, "Login startup: enabled")
			return nil
		}
		fmt.Fprintln(out, "Caddy is already running. Use sandbar reload to apply pending changes.")
		return configurationStatus(c, p, active, nil, out, errOut)
	}
	if state.State != "inactive" && state.State != "failed" {
		return fmt.Errorf("cannot start Caddy with service state %s", state.State)
	}
	if err := changeRoutes(p, "start", nil, out, errOut); err != nil {
		return err
	}
	if err := p.installed.Service.Control("start", out, errOut); err != nil {
		return fmt.Errorf("start Caddy: %w; see %s", err, installedLogGuidance(p.installed))
	}
	c, err := readConfig(p.config)
	if err != nil {
		return err
	}
	if err := waitForInstalledStartup(p, c); err != nil {
		return err
	}
	fmt.Fprintln(out, "HTTPS:", c.routeURL("sandbar.localhost"))
	for _, r := range c.Routes {
		fmt.Fprintln(out, "HTTPS:", c.routeURL(r.Hostname))
	}
	fmt.Fprintln(out, "Root certificate:", p.rootCertificate())
	fmt.Fprintln(out, "Caddy logs:", installedLogGuidance(p.installed))
	return nil
}

func publishGenerated(p paths, data []byte) error {
	if err := checkAcceptedInputs(p); err != nil {
		return err
	}
	if err := p.writeFile(p.generatedPath(), data); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p.generatedPath()))
}
