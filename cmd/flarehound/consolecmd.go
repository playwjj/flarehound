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
	"github.com/playwjj/flarehound/internal/notify"
	"github.com/playwjj/flarehound/internal/report"
	"github.com/playwjj/flarehound/internal/store"
)

const consoleUsage = `Web console (set "console": {"enabled": true} first; blocking needs the write token in the console's environment):

  flarehound console [--listen ADDR]               serve the console (default console.listen, 127.0.0.1:8640)
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
	listen := fs.String("listen", "", "serve: listen address, overriding console.listen (e.g. 0.0.0.0:8640 inside a container)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if verb == "help" {
		fmt.Print(consoleUsage)
		return 0
	}
	// The console sends no alerts: notification variables it lacks are not
	// errors here (the watch checks them, and reports them to the console).
	cfg, err := config.LoadWith(cfgPath, config.LoadOptions{NotifySecretsOptional: true})
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	redactor.Add(cfg.Secrets()...)
	if *listen != "" {
		cfg.Console.Listen = *listen
	}

	db, err := console.OpenDB(cfg.Console.DBFile)
	if err != nil {
		log.Printf("console database: %v", err)
		return 1
	}
	defer db.Close()

	switch verb {
	case "serve":
		redactorAdd = func(s string) { redactor.Add(s) }
		return serveConsole(ctx, cfg, cfgPath, db)
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

// redactorAdd registers a secret with the log redactor.
var redactorAdd = func(string) {}

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

func serveConsole(ctx context.Context, cfg *config.Config, cfgPath string, db *console.DB) int {
	cs := cfg.Console
	if !cs.Enabled {
		log.Print(`the console is off: set "console": {"enabled": true} in the config to serve it`)
		return 1
	}
	if cfg.Archive.Disabled {
		log.Print("the console reads the local archive, but archive.disabled is true")
		return 1
	}
	// The write token lives in this process only (never in the watch):
	// present, admins can block from the console; absent, it is read-only.
	writeToken := os.Getenv(cfg.Blocking.WriteTokenEnv)
	if writeToken != "" {
		redactorAdd(writeToken)
		if !cs.RequireTOTP {
			log.Print("note: the console holds the write token but console.require_totp is off — consider requiring two-factor sign-in")
		}
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
	// Live views (read token): the last hour with the watch's own
	// queries, and the movers' drill-down.
	srv.Measure, srv.Analytics, srv.Caps = runner.Measure, cfapi.New(cfg.APIToken), runner.Caps
	// Settings managed in the console (notifications, alert lines, known
	// faces): an overlay next to the state file, picked up by the watch.
	srv.CfgPath = cfgPath
	if err := srv.RefreshSettings(); err != nil {
		log.Printf("console: settings: %v", err)
	}
	// Password reset by e-mail through notify.email (SMTP or Resend).
	if e := cfg.Notify.Email; e != nil && cs.BaseURL != "" {
		srv.Mail = console.EmailSender(notify.Email{Provider: e.Provider, Host: e.Host, Port: e.Port, TLS: e.TLS, Username: e.Username,
			Password: cfg.Chan.EmailPassword, From: e.From})
	}
	// WAF rules: listed with the read token (Zone → WAF: Read), changed
	// with the write token; backups and the change log live in the archive.
	srv.RulesRead, srv.Store = cfapi.NewREST(cfg.APIToken), st
	mode := "read-only"
	if writeToken != "" {
		srv.Write, srv.Live, srv.Store = cfapi.NewREST(writeToken), cfapi.New(cfg.APIToken), st
		srv.RulesWrite = cfapi.NewREST(writeToken)
		mode = "blocking enabled for admins"
	}
	go srv.Background(ctx) // keeps slow pages warm (and, with the write token, blocks and effects)
	if srv.CanWrite() {
		// The console holds the write token: it lifts expired blocks itself
		// (a separate `flarehound enforce` is no longer required).
		go srv.ExpiryLoop(ctx)
		mode += ", lifts expired blocks"
	}
	hs := &http.Server{Addr: cs.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}

	ln, err := net.Listen("tcp", cs.Listen)
	if err != nil {
		log.Printf("console: %v", err)
		return 1
	}
	log.Printf("flarehound %s console listening on http://%s (%s)", version, ln.Addr(), mode)
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
				ps, err := db.Prune()
				if err != nil {
					log.Printf("console: prune: %v", err)
				} else if ps.Snapshots+ps.Audit+ps.Effects > 0 {
					log.Printf("console: pruned %d snapshot page(s), %d audit entries, %d cached comparisons", ps.Snapshots, ps.Audit, ps.Effects)
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
