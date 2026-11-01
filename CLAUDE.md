# Projektkontext für Claude Code

Sitewatch zur Überwachung und Wartung von Contao-/PHP-Webseiten (Eigentümer: Software-Architekt, Go- und Contao-erfahren).
Sprache der UI, Texte und Kommentare: Deutsch. Code-Bezeichner: Englisch bzw. wie im vorhandenen Code.

## Architekturentscheidungen (nicht ohne Rückfrage ändern)
- **Nur ausgehende Verbindungen von den Agenten.** Auf Zielservern wird kein Port geöffnet. Reports werden gepusht; Aufträge holt der Agent später per Polling ab (optional später WebSocket mit Polling-Fallback).
- Agent in Go, ein statisches Binary pro Server. PHP-Bundle/Cron-Skript nur für Shared Hosting, gleiches JSON-Schema (`internal/report`).
- Sitewatch in Go, server-gerenderte Oberfläche (html/template, kein SPA). Ziel-Datenbank: SQLite hinter dem Interface `store.Store`.
- **Agent-Typen:** Server-Agent (`go-host`) und Contao-Bundle (`contao-bundle`, `report.AgentContaoBundle`). Das Bundle ist ein Agent mit genau einer Site (Site-ID = Agent-ID), holt keine Konfiguration und keine Aufträge; für seine Reports gelten eigene Schwellwerte (`BundleStaleAfter`).
- **Weckruf statt Endpunkt.** Für Seiten ohne Server-Cron (PHP-Bundle `cgoit/contao-sitewatch-bundle`, eigenes Repo) darf Sitewatch die öffentliche Seiten-URL anpingen, wenn der Report überfällig ist. Der Ping trägt keine Daten und keine Aufträge, das Bundle hat keinen eigenen Endpunkt; der Report geht weiterhin vom Bundle zu Sitewatch. Aufträge per Ping sind ausgeschlossen. Adresse ist die vom Admin gepflegte `site_url` des Bundle-Agenten (leer = kein Weckruf, keine TLS-Prüfung; nie die URL aus dem Report), nur https, 10 s Timeout, keine Weiterleitungen, keine internen Zieladressen (`internal/probe`). Dieselbe Adresse dient der TLS-Ablaufprüfung per Handshake; das Ergebnis ergänzt den Report, wenn er kein `tls_expires` enthält.
- **Zuerst lesend.** Schreibende Aktionen (Wartungsmodus, Updates) erst nach Sicherheitskonzept: feste Aktionsliste, keine freie Shell, signierte Aufträge (Ed25519) mit Ablaufzeit, Freigabe im Dashboard.
- Tokens nie im Klartext speichern (nur SHA-256-Hash). Agenten samt Token-Hash stehen in der SQLite-Datenbank (Tabelle `agents`); `tokens.json` und `sitewatch token` gibt es nicht mehr, `agents.json` wird nur einmalig importiert. Schwellwerte pflegt man im Cockpit (Seite „Einstellungen“, Tabelle `meta`, nur Abweichungen vom Standard); `-thresholds` und `-stale` gibt es nicht mehr. Die Konfiguration (Agenten, Schwellwerte) lässt sich unter „Einstellungen“ exportieren und mit `serve -import` in eine leere Installation einspielen (`internal/backup`); `signing.key` bleibt bewusst eine Datei und ist nicht Teil des Exports. Sitewatch ist das einzige eingehend erreichbare Ziel und muss entsprechend gehärtet werden.

## Konventionen
- Möglichst Standardbibliothek; neue Abhängigkeiten nur mit Grund (SQLite-Treiber ist der erste Kandidat).
- Das Datenbankschema ändert man nur über einen Eintrag in `migrations` (`internal/store/sqlite.go`, `PRAGMA user_version`), nie durch Ändern von `schema`; eine neuere Datenbank lehnt das Programm ab.
- `go vet ./... && go test ./...` müssen grün sein, `gofmt` sauber.
- Alles in `testdata/` und `scripts/demo.sh` sind Beispieldaten/Stubs und als solche zu kennzeichnen.
- Fehlende Daten sind `nil`/leer, nie geraten. Was der Agent nicht ermitteln konnte, steht in `site.problems`.

## Offene Entscheidungen
- Pflichtfelder im Report, wenn nur das PHP-Bundle liefert (`host`-Daten fehlen).
- Aufbewahrungsdauer der Historie.
- Zugang zu Sitewatch: Passkey oder TOTP, IP-Beschränkung, mTLS.
Weitere Schritte: siehe `docs-intern/roadmap.md` (lokal, nicht im Repo) und README.md.
