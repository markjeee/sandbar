package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const routeCheckTimeout = 3 * time.Second

// Status observes committed and active state. It never resolves a transaction.
func status(p paths, out, errOut io.Writer) error {
	var failures []error
	active, adminErr := readActiveConfig(p)
	stopped := isRouterStopped(adminErr)
	switch {
	case adminErr == nil:
		fmt.Fprintln(out, "Router: running")
	case stopped:
		fmt.Fprintln(out, "Router: stopped")
		failures = append(failures, errors.New("router is stopped"))
	default:
		fmt.Fprintln(out, "Router: inaccessible")
		failures = append(failures, fmt.Errorf("query private admin endpoint: %w", adminErr))
	}
	journal := p.file("transaction")
	if _, err := os.Lstat(journal); err == nil {
		fmt.Fprintln(out, "Recovery: pending:", journal)
		failures = append(failures, fmt.Errorf("recovery is pending: %s", journal))
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(out, "Recovery: inaccessible:", journal)
		failures = append(failures, fmt.Errorf("inspect recovery state: %w", err))
	} else {
		fmt.Fprintln(out, "Recovery: none")
	}
	c, err := readConfig(p.config)
	if err != nil {
		fmt.Fprintln(out, "Configuration: invalid:", err)
		return errors.Join(append(failures, err)...)
	}
	if err := configurationStatus(c, p, active, adminErr, out, errOut); err != nil {
		failures = append(failures, err)
	}
	if len(c.Routes) == 0 {
		fmt.Fprintln(out, "Routes: none")
		return errors.Join(failures...)
	}
	if stopped {
		for _, r := range c.Routes {
			fmt.Fprintln(out, c.routeURL(r.Hostname), "not checked (router stopped)")
		}
		return errors.Join(failures...)
	}
	root := p.file("caddy/pki/authorities/local/root.crt")
	roots, rootErr := selectedStatusRoots(root)
	for _, r := range c.Routes {
		if rootErr != nil {
			fmt.Fprintln(out, c.routeURL(r.Hostname), "TLS error:", rootErr)
			continue
		}
		code, err := checkHTTPSRoute(c, r, roots)
		if err != nil {
			kind := "connection error"
			var tlsErr *routeTLSError
			if errors.As(err, &tlsErr) {
				kind = "TLS error"
			}
			fmt.Fprintf(out, "%s %s: %v\n", c.routeURL(r.Hostname), kind, err)
			failures = append(failures, fmt.Errorf("%s: %w", r.Hostname, err))
			continue
		}
		if code >= 500 {
			fmt.Fprintf(out, "%s HTTP %d (failure)\n", c.routeURL(r.Hostname), code)
			failures = append(failures, fmt.Errorf("%s returned HTTP %d", r.Hostname, code))
		} else {
			fmt.Fprintf(out, "%s HTTP %d (reachable)\n", c.routeURL(r.Hostname), code)
		}
	}
	if rootErr != nil {
		failures = append(failures, rootErr)
	}
	return errors.Join(failures...)
}

func configurationStatus(c config, p paths, active []byte, adminErr error, out, errOut io.Writer) error {
	generated, err := os.ReadFile(p.file("Caddyfile"))
	if err != nil {
		fmt.Fprintln(out, "Configuration: pending (generated configuration unavailable)")
		return fmt.Errorf("read generated configuration: %w", err)
	}
	ipv4, err := renderCaddyfile(c, p, false)
	if err != nil {
		return err
	}
	ipv6, err := renderCaddyfile(c, p, true)
	if err != nil {
		return err
	}
	var failures []error
	if !bytes.Equal(generated, []byte(ipv4)) && !bytes.Equal(generated, []byte(ipv6)) {
		fmt.Fprintln(out, "Configuration: pending (source differs from generated configuration)")
		failures = append(failures, errors.New("source configuration has pending changes"))
	}
	if adminErr == nil {
		adapted, err := adaptCaddyfile(p, p.file("Caddyfile"), errOut)
		if err != nil {
			fmt.Fprintln(out, "Configuration: unknown (cannot inspect generated configuration)")
			failures = append(failures, err)
		} else if !jsonEqual(adapted, active) {
			fmt.Fprintln(out, "Configuration: pending (generated configuration differs from active configuration)")
			failures = append(failures, errors.New("generated configuration has pending changes"))
		} else if len(failures) == 0 {
			fmt.Fprintln(out, "Configuration: current")
		}
	} else if len(failures) == 0 {
		if isRouterStopped(adminErr) {
			fmt.Fprintln(out, "Configuration: saved (router stopped)")
		} else {
			fmt.Fprintln(out, "Configuration: unknown (active configuration inaccessible)")
		}
	}
	return errors.Join(failures...)
}

func selectedStatusRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read selected root certificate %s: %w", path, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("selected root certificate contains no certificates: %s", path)
	}
	return roots, nil
}

type routeTLSError struct{ error }

func (e *routeTLSError) Unwrap() error { return e.error }

func checkHTTPSRoute(c config, r route, roots *x509.CertPool) (int, error) {
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{
		// Dial loopback directly, while retaining the configured name for TLS and HTTP.
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.HTTPSPort)))
			if err != nil {
				return nil, err
			}
			secured := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: r.Hostname, MinVersion: tls.VersionTLS12})
			if err := secured.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, &routeTLSError{err}
			}
			return secured, nil
		},
		ResponseHeaderTimeout: routeCheckTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   routeCheckTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequest(http.MethodHead, c.routeURL(r.Hostname)+"/", nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	response.Body.Close()
	return response.StatusCode, nil
}
