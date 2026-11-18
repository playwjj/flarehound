package main

// flarehound console — the web console (docs/web-console-revision.md).
// A separate process from the watch: it reads the archive the watch
// writes and keeps its own account database. v1.3 is read-only against
// Cloudflare and never reads the write token.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/playwjj/flarehound/internal/cfapi"
	"github.com/playwjj/flarehound/internal/check"
	"github.com/playwjj/flarehound/internal/config"
	"github.com/playwjj/flarehound/internal/console"
	"github.com/playwjj/flarehound/internal/health"
	"github.com/playwjj/flarehound/internal/logx"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/store"
)

const consoleUsage = `Web console (v1.3, read-only; set "console": {"enabled": true} first):

  flarehound console                               serve the console (default 127.0.0.1:8640)
  flarehound console init-admin --user NAME [--email ADDR]
                                                   create an admin account (password from the
                                                   terminal, or FLAREHOUND_ADMIN_PASSWORD)
  flarehound console users                         list accounts
  flarehound console reset-password --user NAME    set a new password, unlock, end sessions
  flarehound console reset-totp --user NAME        turn off two-factor sign-in for an account
`

func runConsole(ctx context.Context, cfgPath string, args []string, redactor *logx.Redactor) int {
	verb := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		verb, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("console "+verb, flag.ContinueOnError)
	fs.StringVar(&cfgPath, "config", cfgPath, "path to config file")
	user := fs.String("user", "", "account name")
	email := fs.String("email", "", "e-mail address (optional)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if verb == "help" {
		fmt.Print(consoleUsage)
		return 0
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	redactor.Add(cfg.Secrets()...)

	db, err := console.OpenDB(cfg.Console.DBFile)
	if err != nil {
		log.Printf("console database: %v", err)
		return 1
	}
	defer db.Close()

	switch verb {
	case "serve":
		return serveConsole(ctx, cfg, db)
	case "init-admin":
		if *user == "" {
			fmt.Fprint(os.Stderr, "init-admin needs --user NAME\n")
			return 2
		}
		pw, err := readNewPassword()
		if err != nil {
			log.Print(err)
			return 1
		}
		u, err := db.CreateUser(*user, *email, pw, console.RoleAdmin, false)
		if err != nil {
			log.Printf("init-admin: %v", err)
			return 1
		}
		_ = db.Audit("cli", "local", "user_created", u.Username, "admin via init-admin")
		fmt.Printf("admin %q created\n", u.Username)
		return 0
	case "users":
		us, err := db.Users()
		if err != nil {
			log.Print(err)
			return 1
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "USER\tROLE\tSTATUS\t2FA\tEMAIL")
		for _, u := range us {
			st := "active"
			switch {
			case u.Disabled:
				st = "disabled"
			case time.Now().Before(u.LockedUntil):
				st = "locked"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\n", u.Username, u.Role, st, u.TOTPEnabled, u.Email)
		}
		tw.Flush()
		return 0
	case "reset-password", "reset-totp":
		if *user == "" {
			fmt.Fprintf(os.Stderr, "%s needs --user NAME\n", verb)
			return 2
		}
		u, ok, err := db.UserByName(*user)
		if err != nil || !ok {
			log.Printf("%s: no account %q", verb, *user)
			return 1
		}
		if verb == "reset-totp" {
			if err := db.SetTOTP(u.ID, "", false, 0); err != nil {
				log.Print(err)
				return 1
			}
			_ = db.EndUserSessions(u.ID, "")
		} else {
			pw, err := readNewPassword()
			if err != nil {
				log.Print(err)
				return 1
			}
			if err := db.SetPassword(u.ID, pw, false, ""); err != nil {
				log.Print(err)
				return 1
			}
		}
		_ = db.Audit("cli", "local", strings.ReplaceAll(verb, "-", "_"), u.Username, "")
		fmt.Printf("%s: done for %q (all sessions ended)\n", verb, u.Username)
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown console command %q\n\n%s", verb, consoleUsage)
	return 2
}

func readNewPassword() (string, error) {
	if pw := os.Getenv("FLAREHOUND_ADMIN_PASSWORD"); pw != "" {
		return pw, console.CheckPasswordPolicy(pw)
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Piped input: one line.
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("no password: run in a terminal or set FLAREHOUND_ADMIN_PASSWORD")
		}
		pw := strings.TrimRight(line, "\r\n")
		return pw, console.CheckPasswordPolicy(pw)
	}
	fmt.Fprintf(os.Stderr, "New password (at least %d characters): ", console.MinPasswordLen)
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if err := console.CheckPasswordPolicy(string(a)); err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("the two passwords differ")
	}
	return string(a), nil
}

// listenIsLocal reports whether a listen address binds loopback only.
func listenIsLocal(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func serveConsole(ctx context.Context, cfg *config.Config, db *console.DB) int {
	cs := cfg.Console
	if !cs.Enabled {
		log.Print(`the console is off: set "console": {"enabled": true} in the config to serve it`)
		return 1
	}
	if cfg.Archive.Disabled {
		log.Print("the console reads the local archive, but archive.disabled is true")
		return 1
	}
	// v1.3 is read-only: the write token belongs to the CLI only (and to
	// the console from v1.4, behind its own isolation rules).
	if os.Getenv(cfg.Blocking.WriteTokenEnv) != "" {
		log.Printf("warning: %s is set in the console's environment. This console version never uses it — remove it from this process.", cfg.Blocking.WriteTokenEnv)
	}
	if !listenIsLocal(cs.Listen) {
		log.Printf("warning: console.listen %s is not loopback-only. FlareHound does no TLS: put it behind Tailscale, a TLS reverse proxy or Cloudflare Tunnel, and list that proxy in console.trusted_proxies.", cs.Listen)
	}

	st, err := store.Open(cfg.Archive.File)
	if err != nil {
		log.Printf("archive: %v", err)
		return 1
	}
	defer st.Close()

	runner := &check.Runner{API: cfapi.New(cfg.APIToken), Cfg: cfg, Rules: cfapi.NewREST(cfg.APIToken)}
	auditor := func(ctx context.Context, z config.Zone) (report.AuditData, error) { return runner.Audit(ctx, z) }

	srv, setup, err := console.New(cfg, db, st, auditor, version)
	if err != nil {
		log.Printf("console: %v", err)
		return 1
	}
	hs := &http.Server{Addr: cs.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}

	ln, err := net.Listen("tcp", cs.Listen)
	if err != nil {
		log.Printf("console: %v", err)
		return 1
	}
	log.Printf("flarehound %s console listening on http://%s (read-only)", version, ln.Addr())
	if setup != "" {
		base := cs.BaseURL
		if base == "" {
			base = "http://" + ln.Addr().String()
		}
		log.Printf("no accounts yet — create the first admin at %s/setup?token=%s (or run `flarehound console init-admin --user NAME`)", base, setup)
	}

	beat := func() {
		b := health.Beat{At: time.Now().UTC(), Version: version, Role: "console", Zones: len(cfg.Cloudflare.Zones),
			Listen: ln.Addr().String(), WriteTokenInEnv: os.Getenv(cfg.Blocking.WriteTokenEnv) != ""}
		if err := health.Write(cfg.DataDir(), health.ConsoleFile, b); err != nil {
			log.Printf("console: heartbeat: %v", err)
		}
	}
	beat()
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				beat()
			}
		}
	}()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := db.PruneSessions(); err != nil {
					log.Printf("console: prune sessions: %v", err)
				}
			}
		}
	}()
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
		log.Print("console: shut down")
		return 0
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		log.Printf("console: %v", err)
		return 1
	}
}
