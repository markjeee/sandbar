package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func listRoutes(p paths, out io.Writer) error {
	c, err := readConfig(p.config)
	if err != nil {
		return err
	}
	for _, r := range c.Routes {
		fmt.Fprintf(out, "%s\t%s\t%s\n", r.Hostname, c.routeURL(r.Hostname), r.Upstream)
	}
	return nil
}

func changeRoutes(p paths, command string, args []string, out, errOut io.Writer) error {
	if err := recoverTransaction(p, errOut); err != nil {
		return err
	}
	previousSource, err := os.ReadFile(p.config)
	if err != nil {
		return err
	}
	c, err := decodeConfig(bytes.NewReader(previousSource))
	if err != nil {
		return err
	}
	legacy := c.Version == 1
	switch command {
	case "add":
		flags := flag.NewFlagSet("add", flag.ContinueOnError)
		flags.SetOutput(errOut)
		replace := flags.Bool("replace", false, "replace an existing upstream")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if flags.NArg() != 2 {
			return errors.New("add requires a hostname and upstream")
		}
		hostname, err := normalizeHostname(flags.Arg(0))
		if err != nil {
			return err
		}
		upstream, err := normalizeUpstream(flags.Arg(1), c.HTTPPort, c.HTTPSPort)
		if err != nil {
			return err
		}
		found := false
		for i, r := range c.Routes {
			if r.Hostname != hostname {
				continue
			}
			found = true
			if r.Upstream == upstream && !legacy {
				fmt.Fprintln(out, "Route unchanged:", hostname)
				return nil
			}
			if r.Upstream != upstream && !*replace {
				return fmt.Errorf("route %s already exists with another upstream; use --replace", hostname)
			}
			c.Routes[i].Upstream = upstream
		}
		if !found {
			c.Routes = append(c.Routes, route{hostname, upstream})
		}
	case "rm":
		if len(args) != 1 {
			return errors.New("rm requires a hostname")
		}
		hostname, err := normalizeHostname(args[0])
		if err != nil {
			return err
		}
		found := false
		for i, r := range c.Routes {
			if r.Hostname == hostname {
				c.Routes = append(c.Routes[:i], c.Routes[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown route %s", hostname)
		}
	case "reload", "start":
	default:
		return fmt.Errorf("unknown route command %s", command)
	}
	// Manual reload retains the source version and exact edited bytes.
	candidateSource := previousSource
	if command != "reload" && command != "start" {
		c.Version = 2
		c.Hostname = ""
		c.UpstreamPort = 0
		if err := c.validate(); err != nil {
			return err
		}
		candidateSource, err = configBytes(c)
		if err != nil {
			return err
		}
	}
	if err := checkSelectedCaddy(p, caddyEnv(p), errOut); err != nil {
		return err
	}
	ipv6, err := ipv6Available(probeIPv6, errOut)
	if err != nil {
		return err
	}
	if p.installed != nil && p.installed.ID == "sandbar-launchd-v1" {
		record, err := readSetupRecord(p)
		if err != nil {
			return err
		}
		if record.SocketPlan == nil {
			return errors.New("missing launchd socket plan")
		}
		ipv6 = record.SocketPlan.IPv6
	}
	content, err := renderCaddyfile(c, p, ipv6)
	if err != nil {
		return err
	}
	var adapted []byte
	if p.installed != nil {
		adapted, err = installedCandidate(p, []byte(content), c, out, errOut)
		if err != nil {
			return err
		}
	} else {
		candidate, err := os.CreateTemp(p.state, ".Caddyfile-*")
		if err != nil {
			return err
		}
		defer os.Remove(candidate.Name())
		_, writeErr := io.WriteString(candidate, content)
		if err := errors.Join(writeErr, candidate.Close()); err != nil {
			return err
		}
		if err := invokeCaddy(caddyEnv(p), nil, out, errOut, "validate", "--config", candidate.Name(), "--adapter", "caddyfile"); err != nil {
			return err
		}
		adapted, err = adaptCaddyfile(p, candidate.Name(), errOut)
		if err != nil {
			return err
		}
	}
	active, activeErr := selectedActiveConfig(p)
	running := activeErr == nil
	if activeErr != nil && !isRouterStopped(activeErr) {
		return fmt.Errorf("inspect private admin endpoint: %w", activeErr)
	}
	if command == "reload" && !running {
		return errors.New("router is stopped; start it to apply source configuration")
	}
	if p.installed != nil && running {
		committed, err := committedAdaptedConfig(p, errOut)
		if err != nil {
			return err
		}
		if !jsonEqual(committed, active) {
			return errors.New("active Caddy configuration differs from the accepted service files; review setup before changing routes")
		}
	}
	previousGenerated, err := readOptional(p.file("Caddyfile"))
	if err != nil {
		return err
	}
	tx := transaction{Version: 1, Phase: "prepared", Reload: running, Migration: legacy && command != "reload",
		PreviousSource: previousSource, CandidateSource: candidateSource, PreviousGenerated: previousGenerated,
		CandidateGenerated: []byte(content), PreviousActive: active, CandidateActive: adapted}
	if err := prepareTransaction(p, &tx); err != nil {
		return err
	}
	if err := checkTransactionFiles(p, tx); err != nil {
		return err
	}
	if err := checkMigrationBackup(p, tx); err != nil {
		return err
	}
	if err := saveTransaction(p, tx); err != nil {
		return err
	}
	if running {
		tx.Phase = "loading"
		if err := saveTransaction(p, tx); err != nil {
			return err
		}
		if err := checkTransactionFiles(p, tx); err != nil {
			return err
		}
		if err := checkMigrationBackup(p, tx); err != nil {
			return err
		}
		var reloadErr error
		if p.installed != nil {
			if err := publishGenerated(p, tx.CandidateGenerated); err != nil {
				return err
			}
			reloadErr = p.installed.Service.Control("reload", out, errOut)
		} else {
			address, _ := p.adminAddress()
			reloadErr = invokeCaddy(caddyEnv(p), nil, out, errOut, "reload", "--config", p.file("transaction/candidate.Caddyfile"), "--adapter", "caddyfile", "--address", address)
		}
		if reloadErr != nil {
			if err := recoverTransaction(p, errOut); err != nil {
				return errors.Join(reloadErr, err)
			}
			return reloadErr
		}
	}
	tx.Phase = "applied"
	if err := saveTransaction(p, tx); err != nil {
		return err
	}
	if err := finishTransaction(p, tx, true); err != nil {
		return err
	}
	fmt.Fprintln(out, "Routes saved:", p.config)
	return nil
}
