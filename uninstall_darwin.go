package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func uninstallSystem(args []string, out, errOut io.Writer) error {
	return errors.New("privileged uninstall is supported only on Linux")
}
func uninstallInstalled(check bool, out, errOut io.Writer) error {
	i, err := inspectInstallation()
	if err != nil {
		return err
	}
	plan, err := buildUninstallPlan(installedPaths(i), os.Getuid(), errOut)
	if err != nil {
		return err
	}
	if err := observeUninstallTeleports(plan); err != nil {
		return err
	}
	printUninstallPlan(plan, out)
	if plan.AlreadyRemoved || check {
		return nil
	}
	// Observe every connection before any current-user trust or SSH change.
	if err := runUninstallUser(plan, out, errOut); err != nil {
		return err
	}
	return finishUninstall(plan, out, errOut)
}
func uninstallBackupRoots(p paths) ([]string, error) {
	return filepath.Glob(p.file("backups/setup-*"))
}
func uninstallPlatformPreflight(plan *uninstallPlan, ownerUID int) error {
	p := plan.Paths
	i := p.installed
	if plan.AlreadyRemoved {
		fragment := filepath.Join(filepath.Dir(i.Fragment), sandbarLaunchdLabel+".plist")
		if _, err := os.Lstat(fragment); err == nil {
			return fmt.Errorf("orphan Sandbar login registration remains: %s; review it manually", fragment)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		candidate := *i
		candidate.Unit = sandbarLaunchdLabel
		if _, err := launchdOutput("/bin/launchctl", "print", launchdTarget(&candidate)); err == nil {
			return errors.New("orphan Sandbar launchd job remains; review it manually")
		} else if !launchdJobMissing(err, candidate.Unit) {
			return err
		}
		return nil
	}
	if i.ID != sandbarLaunchdID || i.UID != ownerUID {
		return errors.New("uninstall requires the current user's verified Sandbar LaunchAgent; review setup --check")
	}
	record, err := readSetupRecord(p)
	if err != nil {
		return err
	}
	if record.SocketPlan == nil {
		return errors.New("missing saved launchd socket plan")
	}
	expected, err := renderLaunchdJob(i, *record.SocketPlan)
	if err != nil {
		return err
	}
	for _, path := range []string{launchdTemplate(i), i.Fragment} {
		data, err := readOptional(path)
		if err != nil {
			return err
		}
		if data == nil && path == i.Fragment {
			continue
		}
		if !bytes.Equal(data, expected) {
			return fmt.Errorf("retain modified launchd job: %s", path)
		}
		if err := plan.addFile(path, ownerUID); err != nil {
			return err
		}
	}
	return nil
}
func uninstallPlatformStop(plan *uninstallPlan, out, errOut io.Writer) error {
	i := plan.Paths.installed
	record, err := readSetupRecord(plan.Paths)
	if err != nil {
		return err
	}
	if record.SocketPlan == nil {
		return errors.New("missing launchd socket plan")
	}
	if err := i.Service.Control("stop", out, errOut); err != nil {
		return err
	}
	state, err := i.Service.Inspect()
	if err != nil {
		return err
	}
	if state.State != "inactive" || state.Boot != "disabled" || state.Sockets != "released" {
		return fmt.Errorf("the Sandbar launchd shutdown is incomplete: state %s, startup %s, sockets %s", state.State, state.Boot, state.Sockets)
	}
	return checkUninstallSocketsReleased(*record.SocketPlan)
}

var uninstallSocketOutput = uninstallSocketCommand

func uninstallSocketCommand(binary string, args ...string) ([]byte, error) {
	var out, diagnostic bytes.Buffer
	err := runBounded(binary, os.Environ(), nil, &out, &diagnostic, args...)
	if err != nil {
		var exit *exec.ExitError
		// lsof returns 1 without diagnostics when no socket matched.
		if errors.As(err, &exit) && exit.ExitCode() == 1 && diagnostic.Len() == 0 {
			return out.Bytes(), nil
		}
		return nil, fmt.Errorf("%s: %w: %s", binary, err, strings.TrimSpace(diagnostic.String()))
	}
	return out.Bytes(), nil
}

func checkUninstallSocketsReleased(plan socketPlan) error {
	// Job/PID shutdown is verified by launchd. Observe ports without binding them.
	for _, protocol := range []string{"TCP", "UDP"} {
		args := []string{"-nP", "-a", "-i" + protocol + ":" + strconv.Itoa(plan.HTTPPort), "-i" + protocol + ":" + strconv.Itoa(plan.HTTPSPort), "-Fpcn"}
		if protocol == "TCP" {
			args = append(args, "-sTCP:LISTEN")
		}
		output, err := uninstallSocketOutput("/usr/sbin/lsof", args...)
		if err != nil {
			return fmt.Errorf("inspect released %s sockets: %w", protocol, err)
		}
		if strings.TrimSpace(string(doctorLocalLsof(output, []int{plan.HTTPPort, plan.HTTPSPort}))) != "" {
			return fmt.Errorf("%s listener remains on the selected ports; retain runtime and CA files", protocol)
		}
	}
	return nil
}
func uninstallPlatformFinish(plan *uninstallPlan, out, errOut io.Writer) error { return nil }
