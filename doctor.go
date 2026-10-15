package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type doctorReport struct {
	out    io.Writer
	failed bool
}

func (d *doctorReport) result(state, check, detail string) {
	fmt.Fprintf(d.out, "%s: %s: %s\n", state, check, detail)
	if state == "failure" {
		d.failed = true
	}
}

func doctor(home string, out, _ io.Writer) error {
	d := &doctorReport{out: out}
	source, err := sourceConfigPath(home)
	if err != nil {
		return err
	}
	mode := "installed"
	if home != "" {
		mode = "development"
	}
	d.result("pass", "selection", mode+"; source "+source)
	p := paths{config: source}
	usable := true
	if home != "" {
		p.state = filepath.Join(filepath.Dir(source), "state")
	} else {
		i, err := doctorInstallation()
		if err != nil {
			d.result("failure", "installation", err.Error())
			usable = false
		} else {
			p = installedPaths(i)
			if err := p.requireSetup(); err != nil {
				d.result("failure", "setup", err.Error())
			} else {
				d.result("pass", "setup", "installation matches setup record")
			}
		}
	}
	c, configErr := readConfig(source)
	if configErr != nil {
		command := "sandbar config --print"
		if home != "" {
			command = selectedCommand(p, "config", "--print")
		}
		d.result("failure", "source", configErr.Error()+"; inspect with "+command)
	} else {
		d.result("pass", "source", "valid")
	}
	binary := "caddy"
	if p.installed != nil {
		binary = p.installed.Binary
	}
	binary, binaryErr := exec.LookPath(binary)
	if binaryErr == nil {
		output, err := doctorCommand(binary, caddyEnv(p), "version")
		if err == nil {
			err = checkCaddyVersion(string(output))
		}
		binaryErr = err
	}
	if binaryErr != nil {
		d.result("failure", "Caddy", binaryErr.Error())
	} else {
		d.result("pass", "Caddy", binary+"; compatible version")
	}
	if !usable {
		d.result("unknown", "service and runtime", "installation discovery failed; identity, admin path, and CA path are unverified")
	} else {
		doctorRuntime(d, p, c, configErr, binary, binaryErr)
	}
	var roots *x509.CertPool
	var rootErr error
	if usable {
		rootPath := p.rootCertificate()
		var fingerprint string
		roots, fingerprint, rootErr = doctorRoot(rootPath)
		if rootErr != nil {
			d.result("failure", "selected CA", rootPath+"; "+rootErr.Error())
		} else {
			d.result("pass", "selected CA", rootPath+"; SHA-256 "+fingerprint)
		}
	} else {
		rootErr = errors.New("installation discovery failed; selected CA is unavailable")
	}
	if configErr == nil {
		doctorPorts(d, c)
		doctorEndpoints(d, p, c, roots, rootErr, home == "", usable)
		doctorTeleports(d, p, c, usable)
	} else {
		d.result("not applicable", "ports, HTTPS, and Teleport", "valid source configuration is required")
	}

	d.result("unknown", "browser", "browser resolution, trust, proxy, and policy behavior require a separate browser check")
	fmt.Fprintln(out, "Observations can become stale. Direct probes bypass proxies and do not identify firewall causes.")
	if d.failed {
		return errors.New("doctor observed failures; no repairs were made")
	}
	fmt.Fprintln(out, "No failures were observed. Unknown checks remain unverified.")
	return nil
}

func doctorCommand(binary string, env []string, args ...string) ([]byte, error) {
	var out, diagnostic bytes.Buffer
	if err := runBounded(binary, env, nil, &out, &diagnostic, args...); err != nil {
		return nil, fmt.Errorf("%s %s: %w", filepath.Base(binary), args[0], err)
	}
	return out.Bytes(), nil
}

func doctorRuntime(d *doctorReport, p paths, c config, configErr error, binary string, binaryErr error) {
	if p.installed == nil {
		d.result("not applicable", "service", "development mode uses a private Caddy process")
	} else {
		state, err := p.installed.Service.Inspect()
		detail := fmt.Sprintf("%s; startup %s; sockets %s", state.State, state.Boot, state.Sockets)
		if err != nil {
			d.result("failure", "service", detail+"; "+err.Error())
		} else if state.State != "active" || state.Boot != "enabled" {
			d.result("failure", "service", detail+doctorStartGuidance(p, configErr))
		} else {
			d.result("pass", "service", detail)
		}
	}
	active, adminErr := readActiveConfig(p)
	if adminErr != nil {
		detail := adminErr.Error()
		if isRouterStopped(adminErr) && configErr == nil {
			detail += "; run " + selectedCommand(p, "start")
		}
		d.result("failure", "private admin", detail)
	} else {
		d.result("pass", "private admin", "active configuration is readable")
	}
	if _, err := os.Lstat(p.file("transaction")); err == nil {
		d.result("failure", "recovery", "pending at "+p.file("transaction")+"; review saved recovery before changes")
	} else if !errors.Is(err, os.ErrNotExist) {
		d.result("failure", "recovery", err.Error())
	} else {
		d.result("pass", "recovery", "none")
	}
	if configErr != nil {
		d.result("not applicable", "configuration comparison", "valid source configuration is required")
		return
	}
	generated, err := os.ReadFile(p.generatedPath())
	if err != nil {
		d.result("failure", "generated configuration", err.Error()+"; run "+selectedCommand(p, "reload"))
		return
	}
	ipv4, err4 := renderCaddyfile(c, p, false)
	ipv6, err6 := renderCaddyfile(c, p, true)
	if err4 != nil || err6 != nil {
		d.result("failure", "configuration comparison", errors.Join(err4, err6).Error())
		return
	}
	pending := !bytes.Equal(generated, []byte(ipv4)) && !bytes.Equal(generated, []byte(ipv6))
	if pending {
		d.result("failure", "source comparison", "source differs from generated configuration; run "+selectedCommand(p, "reload"))
	} else {
		d.result("pass", "source comparison", "source matches generated configuration")
	}
	if binaryErr != nil || adminErr != nil {
		d.result("not applicable", "active comparison", "compatible Caddy and readable admin configuration are required")
		return
	}
	path := p.generatedPath()
	if p.installed != nil {
		if err := checkAcceptedInputs(p); err != nil {
			d.result("failure", "active comparison", err.Error())
			return
		}
		path = p.installed.Config
	}
	adapted, err := doctorCommand(binary, caddyEnv(p), "adapt", "--config", path, "--adapter", "caddyfile")
	if err == nil && !json.Valid(adapted) {
		err = errors.New("caddy adaptation returned invalid JSON")
	}
	if err == nil && p.installed != nil {
		adapted, err = installedSocketRuntime(p, adapted, c)
	}
	if err != nil {
		d.result("failure", "active comparison", err.Error())
	} else if !jsonEqual(adapted, active) {
		d.result("failure", "active comparison", "generated configuration differs from active configuration; run "+selectedCommand(p, "reload"))
	} else {
		d.result("pass", "active comparison", "generated configuration matches active configuration")
	}
}

func doctorRoot(path string) (*x509.CertPool, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", errors.New("public root contains no certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	if !certificate.IsCA {
		return nil, "", errors.New("selected certificate is not a CA")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	fingerprint := sha256.Sum256(certificate.Raw)
	return roots, fmt.Sprintf("%X", fingerprint), nil
}

func doctorTeleports(d *doctorReport, p paths, c config, usable bool) {
	if len(c.Teleports) == 0 {
		d.result("not applicable", "Teleport", "no registered destinations")
		return
	}
	for _, destination := range c.Teleports {
		check := "Teleport " + destination.Machine
		if !usable {
			d.result("unknown", check, "installation discovery failed; current-user control path is unavailable")
			continue
		}
		state, err := observeTeleport(p, destination)
		doctorTeleportResult(d, p, destination, state, err)
	}
}

func doctorTeleportResult(d *doctorReport, p paths, destination teleportDestination, state string, err error) {
	check := "Teleport " + destination.Machine
	switch state {
	case "connected":
		d.result("pass", check+" SSH control", "connected for the current user")
		if err := probeTeleportWelcome(destination); err != nil {
			d.result("failure", check+" forwarded HTTPS", err.Error())
		} else {
			d.result("pass", check+" forwarded HTTPS", "machine welcome verified with saved destination CA; remote app health is unverified")
		}
	case "disconnected":
		d.result("warning", check, "disconnected; run "+selectedCommand(p, "teleport", "connect", destination.Machine))
		d.result("not applicable", check+" forwarded HTTPS", "destination is disconnected")
	default:
		detail := "control state is unknown"
		if err != nil {
			detail += "; " + err.Error()
		}
		d.result("unknown", check, detail)
	}
}

func doctorIPv6(p paths, c config) (bool, error) {
	generated, err := os.ReadFile(p.generatedPath())
	if err != nil {
		return false, err
	}
	ipv4, err := renderCaddyfile(c, p, false)
	if err != nil {
		return false, err
	}
	ipv6, err := renderCaddyfile(c, p, true)
	if err != nil {
		return false, err
	}
	if bytes.Equal(generated, []byte(ipv6)) {
		return true, nil
	}
	if bytes.Equal(generated, []byte(ipv4)) {
		return false, nil
	}
	return false, errors.New("generated listener configuration differs from selected source")
}

func doctorDetail(err error) string { return strings.ReplaceAll(err.Error(), "\n", " ") }

func doctorStartGuidance(p paths, configErr error) string {
	if configErr != nil {
		return "; correct source configuration before starting"
	}
	return "; run " + selectedCommand(p, "start")
}
