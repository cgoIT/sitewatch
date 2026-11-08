// Sitewatch nimmt Reports der Agenten entgegen und zeigt den Zustand aller Sites.
//
//	sitewatch serve [-addr :8080] [-data ./data] [-allow-group g] [-allow-sub s] [-allow-email e] [-trusted-proxy ip,cidr] [-no-login] [-alert-to a,b -alert-from x -alert-smtp host:port]
//	sitewatch alert-test -alert-to a,b -alert-from x -alert-smtp host:port
//	sitewatch pubkey [-data ./data]
//	sitewatch version
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sitewatch/internal/agents"
	"sitewatch/internal/alert"
	"sitewatch/internal/backup"
	"sitewatch/internal/eol"
	"sitewatch/internal/login"
	"sitewatch/internal/probe"
	"sitewatch/internal/push"
	"sitewatch/internal/ratelimit"
	"sitewatch/internal/sign"
	"sitewatch/internal/status"
	"sitewatch/internal/store"
	"sitewatch/internal/web"
)

// version wird beim Build per -ldflags "-X main.version=..." gesetzt (scripts/build.sh).
var version = "dev"

func main() {
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "-version" || args[0] == "--version") {
		args[0] = "version"
	}
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "version":
		fmt.Println("sitewatch", version)
	case "serve":
		serve(args)
	case "pubkey":
		pubkey(args)
	case "alert-test":
		alertTest(args)
	default:
		fmt.Fprintln(os.Stderr, "Verwendung: sitewatch serve | sitewatch pubkey | sitewatch alert-test | sitewatch version")
		os.Exit(2)
	}
}

// thresholdsKey: unter diesem Schlüssel stehen die vom Standard abweichenden Schwellwerte (JSON) in der Datenbank.
const thresholdsKey = backup.ThresholdsKey

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8080", "Adresse, auf der gelauscht wird (hinter nginx mit TLS betreiben)")
	data := fs.String("data", "./data", "Verzeichnis für gespeicherte Reports")
	_ = fs.String("tokens", "", "veraltet und ohne Wirkung (Sites mit Token legt man im Dashboard als Agent an)")
	stale := fs.Duration("stale", 0, "veraltet und ohne Wirkung (Schwellwerte pflegt man im Cockpit unter „Einstellungen“)")
	noLogin := fs.Bool("no-login", false, "Oberfläche OHNE Login betreiben (nur lokale Entwicklung)")
	group := fs.String("allow-group", "", "Authentik-Gruppen mit Zugriff (kommagetrennt)")
	sub := fs.String("allow-sub", "", "Benutzer-IDs (OIDC sub) mit Zugriff (kommagetrennt)")
	email := fs.String("allow-email", "", "verifizierte E-Mail-Adressen mit Zugriff (kommagetrennt)")
	proxies := fs.String("trusted-proxy", "", "IPs/CIDRs des Reverse-Proxys, dessen X-Forwarded-For für das Rate-Limit gilt (kommagetrennt)")
	thresholds := fs.String("thresholds", "", "veraltet und ohne Wirkung (Schwellwerte pflegt man im Cockpit unter „Einstellungen“)")
	useEOL := fs.Bool("eol", true, "Support-Enden täglich von endoflife.date abrufen (PHP, Contao, MariaDB, nginx); aus = nur die eingebaute PHP-Tabelle")
	publicURL := fs.String("public-url", "", "Adresse von Sitewatch für den Block der Agenten-Datei (z. B. https://sitewatch.example); leer = https://<Host der Anfrage>")
	signKey := fs.String("signing-key", "", "privater Ed25519-Schlüssel für die Konfiguration der Agenten (Standard: <data>/signing.key, wird angelegt)")
	agentsFile := fs.String("agents", "", "Datei des früheren Speichers, aus der die Agenten einmalig in die Datenbank übernommen werden (Standard: <data>/agents.json)")
	alertTo := fs.String("alert-to", "", "Empfänger der Alarm-E-Mails (kommagetrennt); leer = keine Alarmierung. SMTP-Zugang: SITEWATCH_SMTP_USER/_PASSWORD in der Umgebung")
	alertFrom := fs.String("alert-from", "", "Absender der Alarm-E-Mails")
	alertSMTP := fs.String("alert-smtp", "localhost:25", "SMTP-Server host:port (STARTTLS, wenn angeboten)")
	alertEvery := fs.Duration("alert-interval", time.Minute, "Prüfintervall der Alarmierung")
	importFile := fs.String("import", "", "Sicherung (Export aus „Einstellungen“) in eine leere Installation einspielen, bevor der Server startet")
	_ = fs.Parse(args)

	if *signKey == "" {
		*signKey = filepath.Join(*data, "signing.key")
	}
	if *agentsFile == "" {
		*agentsFile = filepath.Join(*data, "agents.json")
	}
	px, err := ratelimit.ParseProxies(*proxies)
	if err != nil {
		log.Fatalf("-trusted-proxy: %v", err)
	}
	if *thresholds != "" || *stale != 0 {
		log.Print("Hinweis: -thresholds und -stale werden ignoriert. Schwellwerte pflegt man im Cockpit unter „Einstellungen“.")
	}
	cfg := status.DefaultConfig()
	st, err := store.OpenSQLite(filepath.Join(*data, "sitewatch.db"), cfg.Retention)
	if err != nil {
		log.Fatal(err)
	}
	ags, err := agents.Open(st.DB())
	if err != nil {
		log.Fatalf("Agenten: %v", err)
	}
	if *importFile != "" {
		b, err := os.ReadFile(*importFile)
		if err != nil {
			log.Fatalf("-import: %v", err)
		}
		if err := backup.Import(b, ags, st, st); err != nil {
			log.Fatalf("-import %s: %v", *importFile, err)
		}
		log.Printf("Sicherung %s eingespielt", *importFile)
	}
	if raw, ok, err := st.Setting(thresholdsKey); err != nil {
		log.Fatalf("Schwellwerte lesen: %v", err)
	} else if ok {
		var err error
		if cfg, err = cfg.WithJSON(raw); err != nil {
			log.Printf("Gespeicherte Schwellwerte sind ungültig, es gelten die Standardwerte: %v", err)
		}
		st.SetRetention(cfg.Retention)
	}
	// Einmaliger Import der Dateien des früheren Speichers; sie bleiben als Sicherung liegen.
	if n, err := st.ImportFiles(*data, func(e store.Entry) int {
		return int(status.Evaluate(&e.Report, e.ReceivedAt, e.ReceivedAt, cfg).Level) // Eingangszeit = jetzt, "keine Meldung" entfällt
	}); err != nil {
		log.Fatalf("Import der bisherigen Dateien: %v", err)
	} else if n > 0 {
		log.Printf("%d Reports aus %s importiert", n, *data)
	}
	go func() { // verdichten und aufräumen: beim Start und danach täglich
		for {
			if err := st.Maintain(time.Now()); err != nil {
				log.Printf("Verlauf verdichten: %v", err)
			}
			time.Sleep(24 * time.Hour)
		}
	}()
	if *useEOL {
		ep := &eol.Provider{Cache: st}
		cfg.EOL = ep
		go ep.Run(context.Background(), 24*time.Hour)
	}
	settings := status.NewSettings(cfg)
	prober := &probe.Prober{Agents: ags, Store: st, Settings: settings, Now: time.Now, Uptime: st}
	go prober.Run(context.Background(), 5*time.Minute)
	go prober.RunUptime(context.Background())
	withUptime := settings.Get()
	withUptime.Uptime = prober // Evaluate in Oberfläche und Alarm sieht damit „nicht erreichbar“
	settings.Set(withUptime)
	seen := probe.Store{Store: st, P: prober} // Reports samt ermitteltem Zertifikat-Ablauf, für Oberfläche und Alarme
	var testMail func() error
	var mail alert.Sender
	if to := split(*alertTo); len(to) > 0 {
		if *alertFrom == "" || !strings.Contains(*alertSMTP, ":") {
			log.Fatal("-alert-to braucht -alert-from und -alert-smtp als host:port")
		}
		mail = alert.SMTP(*alertSMTP, os.Getenv("SITEWATCH_SMTP_USER"), os.Getenv("SITEWATCH_SMTP_PASSWORD"), *alertFrom, to)
		testMail = func() error { return mail(testSubject, testBody) }
	}
	// Web-Push ist immer eingerichtet; ohne angemeldetes Gerät geht nichts raus. Die Kontaktadresse für den Push-Dienst ist -public-url.
	vapidPriv, vapidPub, err := push.LoadOrCreateKey(filepath.Join(*data, "vapid.key"))
	if err != nil {
		log.Fatalf("VAPID-Schlüssel: %v", err)
	}
	pusher := &push.Sender{Subs: st, Private: vapidPriv, Public: vapidPub, Subscriber: *publicURL}
	if !strings.HasPrefix(*publicURL, "https://") {
		log.Print("Hinweis: Web-Push braucht -public-url (https) als Kontaktadresse; manche Push-Dienste (Apple) lehnen sonst ab")
	}
	if mail == nil {
		log.Print("Hinweis: keine E-Mail-Alarmierung (-alert-to nicht gesetzt); Alarme gehen nur an Geräte mit Push. Ohne angemeldetes Gerät erreicht ein Alarm niemanden.")
	}
	send := func(subject, body string) error { // E-Mail entscheidet über das Wiederholen, Push ist Best-Effort
		var err error
		if mail != nil {
			err = mail(subject, body)
		}
		_ = pusher.Send(subject, body)
		return err
	}
	w := &alert.Watcher{Store: seen, Config: cfg, Settings: settings, Now: time.Now, State: st, Send: send}
	go w.Run(context.Background(), *alertEvery)
	if _, err := os.Stat(filepath.Join(*data, "tokens.json")); err == nil {
		log.Printf("Hinweis: %s wird nicht mehr gelesen. Sites mit eigenem Token müssen im Dashboard als Agent angelegt werden.", filepath.Join(*data, "tokens.json"))
	}
	srv := web.New(seen, cfg)
	srv.Settings = settings
	srv.Probe = prober
	srv.Uptime = st
	srv.SaveSettings = func(c status.Config, vals map[string]int) error {
		if len(vals) == 0 {
			if err := st.DeleteSetting(thresholdsKey); err != nil {
				return err
			}
		} else {
			b, _ := json.Marshal(vals) // map[string]int kann nicht scheitern
			if err := st.SetSetting(thresholdsKey, string(b)); err != nil {
				return err
			}
		}
		st.SetRetention(c.Retention)
		settings.Set(c)
		return nil
	}
	srv.Version, srv.TestMail, srv.Push = version, testMail, pusher
	if srv.SignKey, err = sign.LoadOrCreateKey(*signKey); err != nil {
		log.Fatalf("-signing-key: %v", err)
	}
	srv.Agents = ags
	if n, err := srv.Agents.ImportFile(*agentsFile); err != nil {
		log.Fatalf("Import der Agenten aus %s: %v", *agentsFile, err)
	} else if n > 0 {
		log.Printf("%d Agenten aus %s importiert", n, *agentsFile)
	}
	srv.PublicURL = *publicURL
	srv.Jobs = st
	log.Printf("Öffentlicher Schlüssel für die Agenten: %s", sign.EncodePublicKey(srv.SignKey.Public().(ed25519.PublicKey)))
	handler := srv.Handler()
	if *noLogin {
		log.Print("WARNUNG: Oberfläche läuft ohne Login (-no-login)")
	} else {
		acc := login.Access{Subjects: split(*sub), Emails: split(*email), Groups: split(*group)}
		handler = withLogin(srv, acc)
	}
	hs := &http.Server{
		Addr: *addr, Handler: accessLog(limited(handler, px), px),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
	}
	log.Printf("Sitewatch %s läuft auf http://%s", version, *addr)
	log.Fatal(hs.ListenAndServe())
}

// pubkey gibt den öffentlichen Schlüssel für die Datei der Agenten aus (der private wird bei Bedarf angelegt).
func pubkey(args []string) {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	data := fs.String("data", "./data", "Datenverzeichnis")
	key := fs.String("signing-key", "", "Schlüsseldatei (Standard: <data>/signing.key)")
	_ = fs.Parse(args)
	if *key == "" {
		*key = filepath.Join(*data, "signing.key")
	}
	priv, err := sign.LoadOrCreateKey(*key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sign.EncodePublicKey(priv.Public().(ed25519.PublicKey)))
}

// withLogin schützt die Oberfläche per OIDC. Geheimnisse kommen aus der Umgebung, nicht aus Flags (sichtbar in der Prozessliste):
// SITEWATCH_OIDC_ISSUER, SITEWATCH_OIDC_CLIENT_ID, SITEWATCH_OIDC_CLIENT_SECRET, SITEWATCH_OIDC_REDIRECT_URL,
// SITEWATCH_SESSION_KEY (hex, mind. 32 Byte, z. B. `openssl rand -hex 32`).
func withLogin(srv *web.Server, acc login.Access) http.Handler {
	if err := acc.Validate(); err != nil {
		log.Fatal(err)
	}
	env := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			log.Fatalf("Umgebungsvariable %s fehlt", k)
		}
		return v
	}
	key, err := hex.DecodeString(env("SITEWATCH_SESSION_KEY"))
	if err != nil {
		log.Fatal("SITEWATCH_SESSION_KEY ist kein Hex-String")
	}
	redirect := env("SITEWATCH_OIDC_REDIRECT_URL")
	sessions, err := login.NewSessions(key, 30*24*time.Hour, strings.HasPrefix(redirect, "https://"))
	if err != nil {
		log.Fatal(err)
	}
	sessions.Allow = acc.Allows // Rechte bei jedem Zugriff neu prüfen, nicht nur beim Login
	lg, err := login.New(login.Config{
		Issuer: env("SITEWATCH_OIDC_ISSUER"), ClientID: env("SITEWATCH_OIDC_CLIENT_ID"),
		ClientSecret: env("SITEWATCH_OIDC_CLIENT_SECRET"), RedirectURL: redirect,
	}, func(w http.ResponseWriter, r *http.Request, id login.Identity) {
		if !acc.Allows(id) {
			log.Printf("login: Zugriff verweigert für %q (Gruppen im Token: %q)", id.Subject, id.Groups)
			http.Error(w, "kein Zugriff", http.StatusForbidden)
			return
		}
		sessions.Set(w, id)
		log.Printf("login: angemeldet sub=%q email=%q", id.Subject, id.Email)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
	if err != nil {
		log.Fatal(err)
	}
	srv.Protect = sessions.Require
	srv.Who = func(r *http.Request) string { // wer einen Auftrag freigibt, wird mit gespeichert
		id, ok := sessions.Get(r)
		switch {
		case !ok:
			return ""
		case id.Email != "":
			return id.Email
		}
		return id.Subject
	}
	mux := http.NewServeMux()
	lg.Register(mux)
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if id, ok := sessions.Get(r); ok {
			log.Printf("login: abgemeldet sub=%q", id.Subject)
		}
		sessions.Logout(w, r)
	})
	mux.Handle("/", srv.Handler())
	return mux
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// limited begrenzt Login-Aufrufe und die Agent-API pro Client-IP. Die Grenzen sind bewusst großzügig
// (Agenten melden etwa alle 5 Minuten, ein Spool von bis zu 100 Reports darf als Schub nachgesendet werden).
func limited(next http.Handler, px []netip.Prefix) http.Handler {
	loginH := ratelimit.New(10, 6*time.Second).Middleware(px, next)       // 10 sofort, dann 10/min
	apiH := ratelimit.New(120, 500*time.Millisecond).Middleware(px, next) // 120 sofort (Spool bis 100), dann 120/min
	jobH := ratelimit.New(300, 250*time.Millisecond).Middleware(px, next) // Long-Poll alle ~20 s, während eines Auftrags Ausgabe-Blöcke ca. 2/s
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login", "/callback":
			loginH.ServeHTTP(w, r)
		case "/api/v1/reports", "/api/v1/agent/config":
			apiH.ServeHTTP(w, r)
		default:
			if strings.HasPrefix(r.URL.Path, "/api/v1/agent/jobs") {
				jobH.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

// Unwrap macht Flush und Zeitlimits für http.ResponseController erreichbar (Live-Ansicht der Aufträge).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// accessLog protokolliert jede Anfrage (außer /healthz) mit Client-IP, Status und Dauer.
func accessLog(next http.Handler, px []netip.Prefix) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		log.Printf("http: %s %s -> %d (%s) von %s", r.Method, r.URL.Path, sw.code, time.Since(start).Round(time.Millisecond), ratelimit.ClientIP(r, px))
	})
}

const (
	testSubject = "Sitewatch: Testmail"
	testBody    = "Dies ist eine Testmail von Sitewatch. Die Alarmierung per E-Mail funktioniert.\n"
)

// alertTest schickt eine Testmail mit denselben Angaben wie serve (-alert-to/-from/-smtp, Zugang über SITEWATCH_SMTP_USER/_PASSWORD).
func alertTest(args []string) {
	fs := flag.NewFlagSet("alert-test", flag.ExitOnError)
	to := fs.String("alert-to", "", "Empfänger (kommagetrennt)")
	from := fs.String("alert-from", "", "Absender")
	smtpAddr := fs.String("alert-smtp", "localhost:25", "SMTP-Server host:port")
	fs.Parse(args)
	rcpt := split(*to)
	if len(rcpt) == 0 || *from == "" || !strings.Contains(*smtpAddr, ":") {
		log.Fatal("alert-test braucht -alert-to, -alert-from und -alert-smtp als host:port")
	}
	if err := alert.SMTP(*smtpAddr, os.Getenv("SITEWATCH_SMTP_USER"), os.Getenv("SITEWATCH_SMTP_PASSWORD"), *from, rcpt)(testSubject, testBody); err != nil {
		log.Fatalf("Testmail fehlgeschlagen: %v", err)
	}
	fmt.Println("Testmail an", strings.Join(rcpt, ", "), "versendet")
}
