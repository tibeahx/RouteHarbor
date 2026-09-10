// RouteHarbor is an unprivileged OpenWrt network controller with an embedded UI.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/api"
	"github.com/tibeahx/RouteHarbor/internal/auth"
	"github.com/tibeahx/RouteHarbor/internal/config"
	"github.com/tibeahx/RouteHarbor/internal/control"
	"github.com/tibeahx/RouteHarbor/internal/platform"
	"github.com/tibeahx/RouteHarbor/internal/web"
)

var version = "0.1.0-dev"

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(
			"usage: routeharbor bootstrap|serve|doctor|validate|api|backup|token|as-service|version",
		)
	}
	switch args[0] {
	case "version":
		fmt.Println("RouteHarbor " + version)
		return nil
	case "bootstrap":
		return bootstrap(args[1:])
	case "serve":
		return serve(args[1:])
	case "doctor":
		return doctor(args[1:])
	case "validate":
		return validate(args[1:])
	case "api":
		return request(args[1:])
	case "backup":
		return backup(args[1:])
	case "token":
		return tokenCommand(args[1:])
	case "as-service":
		return asService(args[1:])
	default:
		return errors.New(
			"unknown command; use bootstrap, serve, doctor, validate, api, backup, token, as-service or version",
		)
	}
}

func privateParent(path string) error {
	p := filepath.Dir(path)
	if e := os.MkdirAll(p, 0o700); e != nil {
		return e
	}
	f, e := os.Lstat(p)
	if e != nil || !f.IsDir() || f.Mode().Perm()&0o077 != 0 {
		return errors.New("output directory must be private (0700)")
	}
	return nil
}

func writeSecret(path, secret string) error {
	if e := privateParent(path); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		return errors.New("cannot create private output; choose a new file")
	}
	defer func() { _ = f.Close() }()
	if _, e = f.WriteString(secret + "\n"); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return f.Close()
}

func bootstrap(args []string) error {
	f := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	state := f.String("state", "/etc/routeharbor", "private service state directory")
	out := f.String("token-file", "", "new private token file (required)")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *out == "" {
		return errors.New("--token-file is required; token values are never printed")
	}
	store, e := config.NewStore(*state)
	if e != nil {
		return e
	}
	defer func() { _ = store.Close() }()
	tokens, e := auth.Open(filepath.Join(*state, "auth"))
	if e != nil {
		return e
	}
	if len(tokens.List()) > 0 {
		if t, e := auth.ReadToken(*out); e == nil {
			if _, ok := tokens.Verify(t); ok {
				fmt.Println("Bootstrap already complete; existing credential retained")
				return nil
			}
		}
		return errors.New(
			"already bootstrapped; issue or rotate a token using trusted local access",
		)
	}
	if e = privateParent(*out); e != nil {
		return e
	}
	if _, e = os.Lstat(*out); !os.IsNotExist(e) {
		return errors.New("token output already exists")
	}
	c, t, e := tokens.Issue("admin")
	if e != nil {
		return e
	}
	if e = writeSecret(*out, t); e != nil {
		_ = tokens.Revoke(c.ID)
		return e
	}
	fmt.Printf(
		"RouteHarbor initialized. Credential written to %s (0600). Traffic routing is off.\n",
		*out,
	)
	return nil
}

func serve(args []string) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	state := f.String("state", "/etc/routeharbor", "private state directory")
	runtimeDir := f.String(
		"runtime",
		"/var/run/routeharbor-engines",
		"private temporary engine directory",
	)
	listen := f.String("listen", "127.0.0.1:8787", "management address")
	cert := f.String("tls-cert", "", "TLS certificate for non-loopback access")
	key := f.String("tls-key", "", "TLS private key")
	hosts := f.String("allow-host", "", "comma-separated exact Host header values")
	helperSocket := f.String("helper-socket", "", "privileged helper socket")
	dev := f.Bool(
		"development",
		false,
		"explicitly permit a root development process without network helper",
	)
	if e := f.Parse(args); e != nil {
		return e
	}
	if os.Geteuid() == 0 && (!*dev || *helperSocket != "") {
		return errors.New(
			"the API must run as an unprivileged service user; development root mode cannot use a helper",
		)
	}
	host, port, e := net.SplitHostPort(*listen)
	if e != nil {
		return errors.New("listen must be an IP:port")
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return errors.New("listen host must be an explicit IP")
	}
	if !ip.IsLoopback() && (*cert == "" || *key == "") {
		return errors.New(
			"non-loopback management requires TLS and an explicit trusted --allow-host",
		)
	}
	if !ip.IsLoopback() && *hosts == "" {
		return errors.New("set --allow-host to trusted LAN management host names or addresses")
	}
	if *key != "" {
		info, err := os.Lstat(*key)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("TLS key must be a private regular file (0600)")
		}
	}
	store, e := config.NewStore(*state)
	if e != nil {
		return e
	}
	defer func() { _ = store.Close() }()
	tokens, e := auth.Open(filepath.Join(*state, "auth"))
	if e != nil {
		return e
	}
	if len(tokens.List()) == 0 {
		return errors.New("no credentials; run bootstrap through trusted local access first")
	}
	journal, e := control.NewJournal(filepath.Join(*state, "operations"))
	if e != nil {
		return e
	}
	manager := adapter.NewManager(*runtimeDir)
	rt := control.New(store, manager, journal)
	server := &api.Server{
		Runtime:      rt,
		Tokens:       tokens,
		UI:           web.Handler(),
		AllowedHosts: []string{net.JoinHostPort(host, port)},
	}
	if ip.IsLoopback() {
		server.AllowedHosts = append(server.AllowedHosts, "localhost:"+port)
	}
	if *hosts != "" {
		server.AllowedHosts = append(server.AllowedHosts, strings.Split(*hosts, ",")...)
	}
	if e = wireServices(server, *state, *helperSocket); e != nil {
		return e
	}
	defer func() {
		if service, ok := server.Coverage.(interface{ Close() error }); ok {
			_ = service.Close()
		}
	}()
	srv := &http.Server{
		Addr:              *listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer rt.Close()
	rt.Start()
	done := make(chan error, 1)
	go func() {
		if *cert != "" {
			done <- srv.ListenAndServeTLS(*cert, *key)
		} else {
			done <- srv.ListenAndServe()
		}
	}()
	fmt.Printf("RouteHarbor listening on %s; credentials are required\n", *listen)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(c)
	}
}

func doctor(args []string) error {
	f := flag.NewFlagSet("doctor", flag.ContinueOnError)
	require := f.Bool("require-openwrt", false, "exit nonzero on unsupported platform")
	if e := f.Parse(args); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	report := platform.Detect(ctx)
	e := json.NewEncoder(os.Stdout).Encode(report)
	if e != nil {
		return e
	}
	if *require && !report.Supported {
		return errors.New("platform preflight failed; no network changes applied")
	}
	return nil
}

func validate(args []string) error {
	f := flag.NewFlagSet("validate", flag.ContinueOnError)
	file := f.String("file", "", "configuration JSON file")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *file == "" {
		return errors.New("--file required")
	}
	b, e := readBoundedFile(*file, config.MaxConfigBytes)
	if e != nil {
		return e
	}
	if _, e = config.Decode(b); e != nil {
		return e
	}
	fmt.Println("Configuration valid; no changes applied")
	return nil
}

func readBoundedFile(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if len(b) > int(max) {
		return nil, errors.New("file exceeds byte limit")
	}
	return b, e
}

func request(args []string) error {
	f := flag.NewFlagSet("api", flag.ContinueOnError)
	base := f.String("url", "http://127.0.0.1:8787", "trusted management URL")
	tokenFile := f.String("token-file", "", "private credential file")
	method := f.String("method", "GET", "HTTP method")
	path := f.String("path", "/api/v1/status", "API path without query")
	data := f.String("data", "", "JSON file, or - for stdin")
	rev := f.Uint64("revision", 0, "If-Match revision")
	idem := f.String("idempotency-key", "", "logical operation key")
	out := f.String("out", "", "new private output file (required for secret export)")
	if e := f.Parse(args); e != nil {
		return e
	}
	token, e := auth.ReadToken(*tokenFile)
	if e != nil {
		return e
	}
	u, e := url.Parse(*base)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid management URL")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if u.Scheme != "https" && (u.Scheme != "http" || e != nil || !ip.IsLoopback()) {
		return errors.New(
			"HTTP is allowed only for an explicit loopback IP; use trusted HTTPS elsewhere",
		)
	}
	if !strings.HasPrefix(*path, "/api/v1/") || strings.ContainsAny(*path, "?#") {
		return errors.New("invalid API path")
	}
	u.Path = *path
	var b []byte
	if *data == "-" {
		b, e = io.ReadAll(io.LimitReader(os.Stdin, config.MaxConfigBytes+1))
	} else if *data != "" {
		b, e = readBoundedFile(*data, config.MaxConfigBytes)
	}
	if e != nil || len(b) > config.MaxConfigBytes {
		return errors.New("invalid or oversized request body")
	}
	if *path == "/api/v1/config/export" && *out == "" {
		return errors.New("secret export requires --out; secrets are not printed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, *method, u.String(), bytes.NewReader(b))
	if e != nil {
		return errors.New("invalid API request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if len(b) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if *rev > 0 {
		req.Header.Set("If-Match", strconv.Quote(strconv.FormatUint(*rev, 10)))
	}
	if *idem != "" {
		req.Header.Set("Idempotency-Key", *idem)
	}
	client := http.Client{
		Timeout:       45 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("API connection failed; verify management address and TLS trust")
	}
	defer func() { _ = res.Body.Close() }()
	reply, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if e != nil {
		return e
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var v struct {
			Error struct {
				Code string `json:"code"`
			}
		}
		_ = json.Unmarshal(reply, &v)
		return fmt.Errorf("API returned HTTP %d (%s)", res.StatusCode, v.Error.Code)
	}
	if *out != "" {
		return writeSecret(*out, string(reply))
	}
	_, e = os.Stdout.Write(reply)
	return e
}

func tokenCommand(args []string) error {
	f := flag.NewFlagSet("token", flag.ContinueOnError)
	state := f.String("state", "/etc/routeharbor", "private state directory")
	role := f.String("role", "read", "admin or read")
	out := f.String("out", "", "new private token output")
	revoke := f.String("revoke", "", "credential identifier to revoke")
	if e := f.Parse(args); e != nil {
		return e
	}
	if e := checkAdministrationOwner(*state, "token"); e != nil {
		return e
	}
	s, e := auth.Open(filepath.Join(*state, "auth"))
	if e != nil {
		return e
	}
	if *revoke != "" {
		return s.Revoke(*revoke)
	}
	if *out == "" {
		return errors.New("--out required for a new credential")
	}
	c, t, e := s.Issue(*role)
	if e != nil {
		return e
	}
	if e = writeSecret(*out, t); e != nil {
		_ = s.Revoke(c.ID)
		return e
	}
	fmt.Printf("Credential %s (%s) written to private file\n", c.ID, c.Role)
	return nil
}

func backup(args []string) error {
	f := flag.NewFlagSet("backup", flag.ContinueOnError)
	state := f.String("state", "/etc/routeharbor", "private service state directory")
	recipient := f.String("recipient", "", "age public recipient")
	out := f.String("out", "", "new encrypted backup file")
	if e := f.Parse(args); e != nil {
		return e
	}
	if e := checkAdministrationOwner(*state, "backup"); e != nil {
		return e
	}
	if !strings.HasPrefix(*recipient, "age1") || len(*recipient) > 128 || *out == "" {
		return errors.New("backup requires --recipient age1... and --out")
	}
	binary, e := exec.LookPath("age")
	if e != nil {
		return errors.New("install the supported age package for standard encrypted backups")
	}
	s, e := config.NewStore(*state)
	if e != nil {
		return e
	}
	defer func() { _ = s.Close() }()
	b, e := json.Marshal(s.Get())
	if e != nil {
		return e
	}
	if e = privateParent(*out); e != nil {
		return e
	}
	file, e := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		return e
	}
	defer func() { _ = file.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--encrypt", "--recipient", *recipient)
	cmd.Stdin = bytes.NewReader(b)
	cmd.Stdout = file
	cmd.Stderr = io.Discard
	if e = cmd.Run(); e != nil {
		_ = os.Remove(*out)
		return errors.New("age backup encryption failed")
	}
	if e = file.Sync(); e != nil {
		return e
	}
	return file.Close()
}
