package main

import (
	"fmt"
	"io"
	"os"
)

func changeTrust(p paths, command string, out, errOut io.Writer) error {
	root := p.rootCertificate()
	var args []string
	if command == "trust" {
		address, err := p.adminAddress()
		if err != nil {
			return err
		}
		args = []string{"trust", "--ca", p.caID(), "--address", address}
	} else {
		if _, err := os.ReadFile(root); err != nil {
			return fmt.Errorf("read selected root certificate %s: %w", root, err)
		}
		args = []string{"untrust", "--cert", root}
	}
	// The selected home identifies the CA, not the caller's trust stores.
	env := os.Environ()
	if err := checkSelectedCaddy(p, env, errOut); err != nil {
		return err
	}
	fmt.Fprintln(errOut, "Public root certificate:", root)
	fmt.Fprintln(errOut, "Caddy can change user and system trust stores and request elevated access.")
	if err := invokeSelectedCaddy(p, env, os.Stdin, out, errOut, args...); err != nil {
		if command == "trust" {
			fmt.Fprintln(errOut, "Trust requires the selected Sandbar router to be running.")
		}
		fmt.Fprintln(errOut, "Some trust stores might already have changed. Review Caddy diagnostics and the documented removal steps.")
		return err
	}
	fmt.Fprintf(out, "Caddy %s command completed. Public root certificate: %s\n", command, root)
	if command == "trust" {
		fmt.Fprintln(out, "Verify HTTPS in Chrome. Follow the browser guide for manual import if needed.")
	} else {
		fmt.Fprintln(out, "Remove any manual imports using the browser guide. Verify certificate rejection in a fresh Chrome process.")
	}
	return nil
}
