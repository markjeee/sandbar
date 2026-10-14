package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type teleportInfo struct {
	Protocol  int    `json:"protocol"`
	Machine   string `json:"machine"`
	HTTPSPort int    `json:"https_port"`
	RootPEM   string `json:"root_pem"`
}

func writeTeleportInfo(p paths, out io.Writer) error {
	if err := p.requireSetup(); err != nil {
		return err
	}
	c, err := readConfig(p.config)
	if err != nil {
		return err
	}
	if c.Version != 3 || c.Machine == "" {
		return errors.New("teleport needs a saved machine identity; run setup or development init")
	}
	root, err := os.ReadFile(p.rootCertificate())
	if err != nil {
		return fmt.Errorf("teleport setup is incomplete; read public root: %w", err)
	}
	if err := validateTeleportRoot(string(root)); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(teleportInfo{Protocol: 1, Machine: c.Machine, HTTPSPort: c.HTTPSPort, RootPEM: string(root)})
}
