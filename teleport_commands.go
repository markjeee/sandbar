package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func executeTeleport(p paths, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || commandHelpRequested(args) {
		fmt.Fprint(out, teleportHelp(args))
		return nil
	}
	command, rest := args[0], args[1:]
	if command == "info" {
		if len(rest) != 1 || rest[0] != "--json" {
			return errors.New("teleport info requires --json")
		}
		return writeTeleportInfo(p, out)
	}
	if command != "register" && command != "connect" && command != "disconnect" && command != "ls" && command != "rm" {
		return fmt.Errorf("unknown teleport command %q (use teleport --help)", command)
	}
	if command == "ls" && len(rest) != 0 {
		return errors.New("teleport ls accepts no arguments")
	}
	if command != "register" && command != "ls" && len(rest) != 1 {
		return fmt.Errorf("teleport %s requires a machine name", command)
	}
	return withLock(p, func() error {
		if command == "register" || command == "rm" {
			if err := recoverTransaction(p, errOut); err != nil {
				return err
			}
		}
		source, err := os.ReadFile(p.config)
		if err != nil {
			return err
		}
		c, err := decodeConfig(bytes.NewReader(source))
		if err != nil {
			return err
		}
		if c.Version != 3 {
			return errors.New("teleport requires version 3 configuration; run setup or development init")
		}
		if command == "register" {
			return registerTeleport(p, source, c, rest, out, errOut)
		}
		if command == "ls" {
			return listTeleports(p, c, out)
		}
		machine, err := normalizeMachine(rest[0])
		if err != nil {
			return err
		}
		for i, d := range c.Teleports {
			if d.Machine != machine {
				continue
			}
			switch command {
			case "connect":
				return connectTeleport(p, c, d, out, errOut)
			case "disconnect":
				if err := disconnectTeleport(p, c, d, errOut); err != nil {
					return err
				}
				fmt.Fprintln(out, "Disconnected:", machine)
				return nil
			case "rm":
				if err := disconnectTeleport(p, c, d, errOut); err != nil {
					return err
				}
				c.Teleports = append(c.Teleports[:i:i], c.Teleports[i+1:]...)
				if err := publishConfig(p, source, c, false, out, errOut); err != nil {
					return err
				}
				if _, err := prepareTeleportSSH(p, c.Teleports); err != nil {
					return err
				}
				socket, log, err := teleportRuntime(p, d)
				if err != nil {
					return err
				}
				if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				if err := os.RemoveAll(filepath.Dir(log)); err != nil {
					return err
				}
				fmt.Fprintln(out, "Removed destination:", machine)
				return nil
			}
		}
		return fmt.Errorf("unknown teleport destination %s", machine)
	})
}

func registerTeleport(p paths, source []byte, c config, args []string, out, errOut io.Writer) (result error) {
	flags := flag.NewFlagSet("teleport register", flag.ContinueOnError)
	flags.SetOutput(errOut)
	host := flags.String("host", "", "direct SSH hostname")
	user := flags.String("user", "", "SSH user")
	port := flags.Int("port", 0, "SSH port")
	remoteBin := flags.String("remote-bin", "", "absolute remote Sandbar binary")
	remoteHome := flags.String("remote-home", "", "absolute remote development home")
	if err := flags.Parse(args); err != nil {
		return err
	}
	portSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portSet = true
		}
	})
	if portSet && (*port < 1 || *port > 65535) {
		return errors.New("SSH port must be from 1 through 65535")
	}
	if flags.NArg() != 1 {
		return errors.New("teleport register requires one direct SSH host or alias")
	}
	for _, value := range []string{*remoteBin, *remoteHome} {
		if value != "" && !filepath.IsAbs(value) {
			return errors.New("remote binary and home options must be absolute paths")
		}
		if strings.IndexFunc(value, func(ch rune) bool { return ch < 32 || ch == 127 }) >= 0 {
			return errors.New("remote binary and home paths cannot contain control characters")
		}
	}
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return errors.New("teleport requires the caller's existing SSH agent (SSH_AUTH_SOCK)")
	}
	d, err := resolveTeleportSSH(flags.Arg(0), *host, *user, *port, errOut)
	if err != nil {
		return err
	}
	d.RemoteBin, d.RemoteHome = *remoteBin, *remoteHome
	candidates := append(append([]teleportDestination{}, c.Teleports...), d)
	cfg, err := prepareTeleportSSH(p, candidates)
	if err != nil {
		return err
	}
	committed := append([]teleportDestination{}, c.Teleports...)
	// Only committed settings remain in the derived SSH configuration on return.
	defer func() {
		if _, restoreErr := prepareTeleportSSH(p, committed); restoreErr != nil {
			result = errors.Join(result, fmt.Errorf("restore committed SSH configuration: %w", restoreErr))
		}
	}()
	peer, err := readTeleportPeer(cfg, d, errOut)
	if err != nil {
		return err
	}
	d.Machine, d.HTTPSPort, d.RootPEM = peer.Machine, peer.HTTPSPort, peer.RootPEM
	if d.Machine == c.Machine {
		return errors.New("destination machine name is this machine's identity")
	}
	for _, saved := range c.Teleports {
		if saved.Machine != d.Machine {
			continue
		}
		d.LocalPort = saved.LocalPort
		if !reflect.DeepEqual(saved, d) {
			return errors.New("destination already exists with different settings; remove and register it again")
		}
		return connectTeleport(p, c, saved, out, errOut)
	}
	d.LocalPort, err = availableTeleportPort(c)
	if err != nil {
		return err
	}
	c.Teleports = append(c.Teleports, d)
	if err := publishConfig(p, source, c, false, out, errOut); err != nil {
		return err
	}
	committed = c.Teleports
	if err := connectTeleport(p, c, d, out, errOut); err != nil {
		return fmt.Errorf("destination %s remains registered; retry teleport connect %s: %w", d.Machine, d.Machine, err)
	}
	return nil
}

func availableTeleportPort(c config) (int, error) {
	for range 10 {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			return 0, err
		}
		used := port == c.HTTPPort || port == c.HTTPSPort
		for _, d := range c.Teleports {
			used = used || port == d.LocalPort
		}
		if !used {
			return port, nil
		}
	}
	return 0, errors.New("could not select an unused Teleport forwarding port")
}

func disconnectTeleport(p paths, c config, d teleportDestination, errOut io.Writer) error {
	cfg, err := prepareTeleportSSH(p, c.Teleports)
	if err != nil {
		return err
	}
	socket, _, err := teleportRuntime(p, d)
	if err != nil {
		return err
	}
	return exitTeleportMaster(cfg, socket, d, errOut)
}

func listTeleports(p paths, c config, out io.Writer) error {
	if len(c.Teleports) == 0 {
		return nil
	}
	cfg, err := prepareTeleportSSH(p, c.Teleports)
	if err != nil {
		return err
	}
	for _, d := range c.Teleports {
		socket, _, err := teleportRuntime(p, d)
		if err != nil {
			return err
		}
		state := "disconnected"
		if teleportMasterExists(cfg, socket, d) {
			state = "connected"
		}
		fmt.Fprintf(out, "%s\t%s\t%s\n", d.Machine, c.routeURL(machineHostname(d.Machine)), state)
	}
	return nil
}
