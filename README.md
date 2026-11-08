# Sitewatch

Überwachung und Wartung von Contao- und PHP-Webseiten auf eigenen Servern.

Auf jedem Server läuft ein kleiner **Agent**. Er sammelt Zustandsdaten und schickt sie **ausgehend per HTTPS** an das
**Dashboard**. Auf den Zielservern wird kein Port geöffnet.

Was das Dashboard zeigt (je Site und für den Server):

- Versionen von Contao, PHP, MariaDB und nginx, dazu das Ende der Herstellerunterstützung (endoflife.date)
- offene Composer-Updates und Sicherheitshinweise (`composer outdated/audit`), mit Ausschlussregeln
- letzte Fehler aus den Monolog-Logs, offene Contao-Migrationen, letzter Contao-Cron-Lauf
- freier Speicherplatz, Alter des letzten Backups, Ablauf des TLS-Zertifikats, Wartungsmodus
- SMART-Zustand der Platten (nur `host`-Einträge, über `smartctl` aus smartmontools; der Agent braucht Leserechte auf die Geräte, i. d. R. Root): Gesamturteil „failed“ ist kritisch, defekte/umgelagerte Sektoren sind eine Warnung. Fehlt `smartctl`, erscheint ein Problem („Teilweise keine Daten“); auf VMs ohne echte Platten schaltet man die Abfrage je Site ab (siehe „SMART und RAID“ unten)
- Linux-Software-RAID (mdadm, aus `/proc/mdstat`, nur `host`-Einträge): ein degradierter oder inaktiver Verbund ist kritisch, ein als defekt markiertes Mitglied bei vollständigem Verbund eine Warnung. Hardware-RAID-Controller und ZFS/btrfs sind nicht abgedeckt (einzelne Platten hinter einem Controller nur, wenn `smartctl --scan` sie liefert)
- Verlauf der defekten Sektoren und der fehlenden RAID-Platten als Kurven (bei verdichteten Punkten gilt das Maximum)
- Verlauf und Trends (Kurven, Statusband, Tagesstände) und eine Bewertung OK / Warnung / Kritisch
- Erreichbarkeit und Antwortzeit: Sitewatch ruft die https-Adresse jeder Site regelmäßig auf (Uptime in %, Verlauf je Tag, Latenz)
- Favicon der Site vor dem Namen in der Übersicht (von Sitewatch geholt, siehe „Favicons“)
- Alarmierung per E-Mail, wenn eine Site kritisch wird
- Aufträge aus einer **festen Liste** (z. B. Wartungsmodus, Cache leeren, Snapshot), jeweils mit Freigabe im Dashboard und Live-Ausgabe

Sitewatch ist ein Go-Programm mit serverseitig gerenderter Oberfläche und SQLite als Speicher. Es gibt zwei Binaries:
`sitewatch` (Dashboard) und `sitewatch-agent`.

## Installation (Debian/Ubuntu, amd64 und arm64)

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://cgoit.github.io/sitewatch/key.asc -o /etc/apt/keyrings/sitewatch.asc
echo "deb [signed-by=/etc/apt/keyrings/sitewatch.asc] https://cgoit.github.io/sitewatch stable main" | sudo tee /etc/apt/sources.list.d/sitewatch.list
sudo apt update
sudo apt install sitewatch-agent    # auf den Servern mit Sites
sudo apt install sitewatch          # auf dem Server des Dashboards
```

Die Pakete legen Binary und systemd-Unit an (beim Dashboard auch den Benutzer `sitewatch`), **starten aber nichts**.
Updates kommen mit `apt upgrade`; die Konfiguration bleibt unangetastet. Die `.deb`-Dateien hängen außerdem an jedem
GitHub-Release.

**Reihenfolge bei Updates:** erst die Binaries austauschen (Dashboard und Agenten), dann neue Konfigurationsfelder
eintragen. Der Agent lehnt unbekannte Schlüssel ab. Dashboard und Agenten sollten dieselbe Version haben.

Ohne apt: `scripts/build.sh` (siehe „Selbst bauen") und die Binaries samt Units aus `scripts/systemd/` von Hand installieren.

## Konfiguration

### 1. Dashboard

`/etc/sitewatch/sitewatch.env` ausfüllen (die Vorlage liegt schon dort):

```sh
SITEWATCH_ARGS=-public-url https://sitewatch.example -allow-group sitewatch -trusted-proxy 127.0.0.1
SITEWATCH_OIDC_ISSUER=https://auth.example/application/o/sitewatch/
SITEWATCH_OIDC_CLIENT_ID=...
SITEWATCH_OIDC_CLIENT_SECRET=...
SITEWATCH_OIDC_REDIRECT_URL=https://sitewatch.example/callback
SITEWATCH_SESSION_KEY=...        # openssl rand -hex 32; fest halten, sonst verfallen alle Sitzungen
```

Dann `systemctl enable --now sitewatch`. Der Dienst lauscht auf `127.0.0.1:8080`; davor gehört ein Reverse-Proxy mit TLS
(bei nginx für `/jobs/*/stream` das Puffern ausschalten und `proxy_read_timeout` über 30 s setzen).

- **Login:** OIDC (getestet mit Authentik). Zugriff über `-allow-group`, `-allow-email` oder `-allow-sub`. Ohne Login-Konfiguration
  startet `serve` nicht; nur zum Entwickeln gibt es `-no-login`. Nur `/api/` (Agent-Token) und `/healthz` sind ohne Login erreichbar.
  `-trusted-proxy` ist die IP/das Netz des Proxys, sonst teilen sich alle Clients dessen IP und damit ein Rate-Limit.
- **Daten:** `/var/lib/sitewatch` (`sitewatch.db` mit Reports, Agenten und Aufträgen sowie `signing.key`). Gehört in die Sicherung;
  ohne `signing.key` müssten alle Agenten den neuen öffentlichen Schlüssel erhalten. Die Datenbank sichert man mit
  `sqlite3 sitewatch.db ".backup ziel.db"`.
- **Push-Nachrichten:** Unter „Einstellungen“ das Gerät aktivieren (iPhone: Sitewatch zuerst über „Teilen → Zum Home-Bildschirm“ installieren und von dort öffnen). Alarme kommen dann zusätzlich zur E-Mail als Web-Push (höchstens 20 Geräte). Die Sitzung bleibt bei Nutzung bis zu 90 Tage nach dem Login offen. `-public-url` (https) dient als Kontaktadresse für den Push-Dienst; der Schlüssel liegt in `<data>/vapid.key`.
- **Alarm per E-Mail:** `-alert-to`, `-alert-from`, `-alert-smtp`; Zugang über `SITEWATCH_SMTP_USER` und `SITEWATCH_SMTP_PASSWORD`.
  Mit gesetztem `-alert-to` erscheint in der Fußzeile der Knopf „Testmail senden"; ohne Oberfläche geht es mit
  `sitewatch alert-test -alert-to … -alert-from … -alert-smtp …` (Zugang wieder über die beiden Umgebungsvariablen).
- **Schwellwerte:** im Dashboard unter **Einstellungen** (Standardwerte, jeder Wert einzeln änderbar, mit Prüfung auf
  Widersprüche und Knopf „zurücksetzen“). Sie stehen in der Datenbank und gelten sofort für Anzeige und Alarme; die Aufbewahrung
  des Verlaufs greift bei der nächsten täglichen Bereinigung. Gespeichert werden nur Werte, die vom Standard abweichen. Die
  Flags `-thresholds` und `-stale` gibt es nicht mehr (sie werden mit einem Hinweis ignoriert). Standard: keine Meldung nach
  15 Minuten (Server-Agent) bzw. 180 Minuten (Contao-Bundle), Support-Ende 90 Tage vorher, TLS 14 Tage, Backup älter als 36 Stunden,
  Speicher unter 15 % (kritisch unter 5 %), Contao-Cron älter als 2 bzw. 4 Stunden, Wartungsmodus nach 2 bzw. 8 Stunden,
  Verlauf: 30 Tage jeder Punkt, bis 90 Tage alle 6 Stunden, bis 365 Tage einer je Tag.
- **Support-Enden:** Das Dashboard ruft täglich endoflife.date ab (`-eol=false` schaltet das aus).

### 2. Agent anlegen

**Zwei Typen:** der *Server-Agent* (unten) und das *Contao-Bundle* für Hosting ohne eigene Programme (z. B. Shared
Hosting). Beim Anlegen wählst du den Typ. Für das Bundle gibst du Site-ID, Anzeigename und URL an und bekommst statt der
`bootstrap.json` den Block für die `config/config.yaml` mit Token (das Bundle `cgoit/contao-sitewatch-bundle` muss
installiert sein). Es meldet stündlich über den Contao-Cron, ohne Konfiguration abzurufen und ohne Aufträge. Updates,
Sicherheitshinweise, Migrationen, Backups, TLS und Serverwerte prüft es nicht (Anzeige „–“). Für „keine Meldung“ gilt
der Wert „Keine Meldung seit (Contao-Bundle)“ unter Einstellungen (Standard 180 Minuten) statt dem für Server-Agenten.

Im Dashboard unter **Agenten** einen Agenten anlegen (einer je Server). Das Token erscheint **einmalig**, zusammen mit dem
Block für die lokale Datei. Dort legst du auch die Sites fest (Art, URL, Pfade, Backup-Verzeichnis, `ignore_updates`,
„hat keine Datenbank/keinen nginx", `SITE_DIR`).

Auf dem Server `/etc/sitewatch-agent/bootstrap.json` anlegen (`chmod 600`; Vorlagen unter
`/usr/share/doc/sitewatch-agent/examples/`):

```json
{
  "sitewatch": "https://sitewatch.example",
  "agent": "server1",
  "token": "TOKEN-DES-AGENTEN",
  "public_key": "AUSGABE-VON-sitewatch-pubkey",
  "state": "/var/lib/sitewatch-agent",
  "roots": ["/appl"],
  "composer": "/usr/share/sitewatch-agent/docker/composer-in-docker",
  "php": "/usr/share/sitewatch-agent/docker/php-in-docker"
}
```

Dann `systemctl enable --now sitewatch-agent`. Der Agent holt vor jedem Lauf die Konfiguration (Sites, Intervall) signiert vom
Dashboard; den öffentlichen Schlüssel zeigt `sitewatch pubkey -data /var/lib/sitewatch`. Programme (`composer`, `php`, `nginx`,
`mariadb`, `smartctl`), Token und `roots` bleiben lokal, aus dem Dashboard kommen nur Daten. Fällt das Dashboard aus, arbeitet der Agent
mit der zuletzt geprüften Konfiguration weiter, bis sie abläuft.

Für Server, die ohne Dashboard-Konfiguration laufen sollen, gibt es `sitewatch-agent -config datei.json`
(Vorlage und Unit unter `/usr/share/doc/sitewatch-agent/examples/`).

**Art einer Site (`kind`):** `contao` (Contao-Konsole, Migrationen, Cron), `php` (sonstige PHP-Site) und `host` (nur
Servermesswerte: Speicherplatz, nginx, MariaDB; erscheint als eigener Eintrag).

**SMART und RAID (nur `host`-Einträge):** Der Agent fragt die Platten über `smartctl` ab und liest Linux-Software-RAIDs aus
`/proc/mdstat`. Dafür gilt:

- `smartmontools` muss auf dem Server installiert sein (`apt install smartmontools`), und der Agent braucht Leserechte auf die
  Geräte. Die mitgelieferten systemd-Units laufen als Root, das genügt. Läuft er unter einem anderen Benutzer, meldet er
  „SMART nicht lesbar“.
- Liegt `smartctl` im `PATH` des Agenten, ist nichts einzutragen. Nur bei einem anderen Ort oder einem Wrapper-Skript trägt man den
  absoluten Pfad als `"smartctl": "/usr/sbin/smartctl"` ein, und zwar **lokal auf dem Server**, nicht im Dashboard: in der
  `bootstrap.json` (Betrieb mit Dashboard-Konfiguration) bzw. auf oberster Ebene der Datei für `-config` (siehe die Vorlagen unter
  `/usr/share/doc/sitewatch-agent/examples/`). Wie bei `composer` oder `php` bestimmt nur die lokale Datei, welches Programm der Agent
  startet; aus dem Dashboard kommen nur Daten.
- Auf VMs ohne echte Platten gibt es nichts abzufragen, und das fehlende `smartctl` würde als Problem gemeldet. Dort schaltet man die
  Abfrage je Site ab: im Dashboard unter „Agenten“ das Häkchen „keine SMART-Abfrage (VM)“, in einer lokalen Konfigurationsdatei
  `"smart": false` an der Site. Das RAID-Lesen bleibt aktiv und meldet nichts, wenn es keinen md-Verbund gibt.
- Bewertung: SMART „failed“ und ein degradierter oder inaktiver RAID-Verbund sind kritisch, defekte Sektoren und ein als defekt
  markiertes RAID-Mitglied sind eine Warnung. Hardware-RAID-Controller, ZFS und btrfs sind nicht abgedeckt.

**Updates ausschließen:** `"ignore_updates": ["contao/*:6.*", "vendor/paket"]` je Site. Eine Regel ist `paket-glob` (jedes Update)
oder `paket-glob:versions-glob`. Treffer bleiben sichtbar („ausgeschlossen"), zählen aber nicht als offenes Update.

### 3. Aufträge (optional)

Ohne Freigabe auf dem Server fragt der Agent nie nach Aufträgen. Zum Einschalten in der `bootstrap.json` eine Liste
`"actions": [...]` eintragen (Beispiel mit allen Namen: `sitewatch-agent.bootstrap.example.json` unter `/usr/share/doc/sitewatch-agent/examples/`). Sie ist die lokale Obergrenze:
Ein kompromittiertes Dashboard kann nie mehr auslösen. Auf der Agentenseite wählst du dann je Site, welche davon gelten
(Standard: keine). Ausgelöst wird im Dashboard unter **Aufträge** mit Freigabe; Aufträge sind signiert und 10 Minuten gültig.

| Stufe | Aktionen |
|---|---|
| Anzeigen (ein Klick) | `site-status`, `site-doctor`, `site-validate-config`, `contao-snapshot-list`, `db-list` |
| Ändern (Bestätigungsseite) | `contao-cache-refresh`, `contao-filesync`, `contao-snapshot`, `db-snapshot`, `site-restart`, `maintenance-off` |
| Site-ID abtippen | `maintenance-on`, `contao-update` |

Die meisten Aktionen rufen `<SITE_DIR>/bin/site <befehl>` auf (das Werkzeug des Website-Stacks); der Wartungsmodus nutzt die
Contao-Konsole. Es gibt keine freie Shell. `bin/site` läuft als Benutzer des Agenten (meist root) und darf deshalb nicht vom
Web-Benutzer beschreibbar sein.

## Weckruf und TLS-Prüfung für Contao-Bundles

Hat ein Contao-Bundle-Agent eine Seiten-URL (https), prüft Sitewatch alle sechs Stunden per TLS-Handshake das Ablaufdatum des Zertifikats
(es ergänzt den Report, der es nicht kennt) und ruft die Seite einmal auf, wenn der letzte Report älter ist als der Wert „Weckruf an die
Seite“ unter „Einstellungen“ (Standard 90 Minuten), höchstens alle 15 Minuten. Das weckt den Contao-Cron bei Seiten mit wenig Besuchern.
Der Aufruf ist ein einfaches GET ohne Daten; Weiterleitungen und Ziele in privaten Netzen werden nicht verfolgt. Ohne URL passiert nichts.

## Favicons

Die Übersicht zeigt vor dem Namen einer Site ihr Favicon, sofern die Seite eins bereitstellt. Die Oberfläche lädt nie fremde Bilder
(CSP `img-src 'self'`, und der Browser würde die IP des Betrachters an die Kundenseite senden): Sitewatch holt das Symbol selbst, speichert
es in der Datenbank und liefert es unter `/sites/<id>/icon` hinter dem Login aus.

- **Quelle:** die https-Adresse aus der Agent-Konfiguration (nie aus dem Report). Gesucht wird in `<link rel="icon">` und
  `<link rel="shortcut icon">` der Startseite (die ersten 64 KB), danach unter `/favicon.ico`. `apple-touch-icon` zählt nicht.
- **Schranken:** wie beim Ping (nur https, 10 s, keine internen Ziele), mit einer Ausnahme: **Weiterleitungen sind erlaubt**, höchstens 3, nur
  nach https und nur innerhalb derselben Site (gleicher Host und Port, ein `www.` davor zählt nicht). Symbole auf einem anderen Host
  (z. B. einem CDN) werden nicht geholt.
- **Bild:** höchstens 128 KB. Das Format (PNG, ICO, GIF, JPEG) erkennt Sitewatch am Inhalt, nicht am Header der Fremdseite. SVG wird nicht
  übernommen, weil es Skripte enthalten kann. Die Auslieferung setzt `nosniff` und eine CSP mit `sandbox`.
- **Takt:** fällig ist es ohne Symbol sofort und danach alle 6 Stunden, mit Symbol alle 24 Stunden. Ändert sich die Adresse der Site, gilt das
  alte Symbol nicht mehr. Gibt es keins, bleibt die Zeile wie bisher. Es ist nichts einzustellen.
- Die Symbole stehen nicht im Export der Konfiguration; sie werden nach einem Import neu geholt.

## Erreichbarkeit (Ping-Modus)

Für jede Site mit https-Adresse in der Agent-Konfiguration (Server-Agent und Contao-Bundle) ruft Sitewatch die Seite standardmäßig alle
**3 Minuten** auf (wählbar: 1, 3, 5, 15 Minuten; abschaltbar je Site auf der Detailseite unter „Erreichbarkeit“). Gemessen wird die Zeit bis zu den
Antwort-Headern. Der Aufruf ist ein einfaches GET (Kennung `Sitewatch-Uptime`) ohne Daten; Weiterleitungen werden nicht verfolgt, Ziele in
privaten Netzen und http-Adressen werden abgelehnt (wie beim Weckruf). Ohne Adresse passiert nichts.

- **Erreichbar:** 2xx, 3xx, 401 und 403. **Nicht erreichbar:** übrige 4xx/5xx, Zeitüberschreitung, Verbindungsfehler.
- **In Wartung:** 503, wenn der letzte Report den Wartungsmodus meldet, sonst höchstens 15 Minuten lang (der Report kann hinterherhinken).
  Wartung löst keinen Alarm aus und zählt in der Erreichbarkeit nicht als Ausfall.
- **Kritisch** wird eine Site erst nach „Seite nicht erreichbar nach … Fehlschlägen in Folge“ (Standard 3, unter „Einstellungen“); die Alarm-Mail
  kommt über die vorhandene Alarmierung. **Warnung** bei einer Antwortzeit (Median der letzten 5 Prüfungen) über 2000 ms. Die Erreichbarkeit
  der letzten 30 Tage wird unter 99 % markiert (nur Anzeige).
- **Anzeige:** Spalte „Erreichbarkeit“ in der Sites-Übersicht (Prozent, Streifen je Tag über 30 Tage, Antwortzeit) und Karte auf der
  Detailseite (7/30/90 Tage, Ausfälle der letzten 7 Tage).
- **Aufbewahrung:** Einzelmessungen 7 Tage, danach eine Zeile je Tag (bis „Ein Punkt je Tag bis“, Standard 365 Tage). Grob 0,5 MB je Site
  und Jahr (Schätzung). Die Einstellungen je Site stehen im Export der Konfiguration, die Messwerte nicht.
- Fallen mindestens 3 Sites und 80 % der geprüften zugleich aus, zeigt die Übersicht den Hinweis, dass das Problem eher bei Sitewatch (Netz, DNS) liegt; Status und Alarme ändert das nicht.
- Sitewatch misst von einem Standort aus. Eine Störung bei Sitewatch selbst erzeugt Lücken (keine Messung, kein Ausfall), ein Netzproblem
  am Sitewatch-Server kann aber mehrere Sites zugleich als „nicht erreichbar“ zeigen.

## Sichern und Umziehen

- **Datensicherung:** Alles liegt in `<data>/sitewatch.db` (SQLite) und `<data>/signing.key`. Die Datenbank sichert man im laufenden Betrieb mit
  `sqlite3 sitewatch.db "VACUUM INTO '/ziel/sitewatch.db'"`; `signing.key` ist eine Datei (Rechte 0600) und gehört in dieselbe Sicherung.
- **Konfiguration exportieren:** Unter „Einstellungen“ → „Sicherung“ liefert „Konfiguration exportieren“ eine JSON-Datei mit den Agenten
  (samt Token-Hash), den Schwellwerten und den Einstellungen der Erreichbarkeitsprüfung, ohne Reports und ohne Signierschlüssel. Die Datei ist so schützenswert wie die Datenbank.
  Der Export hängt am Login der Oberfläche; mit `-no-login` (nur zum Entwickeln) ist er für alle erreichbar.
- **Umzug:** Auf dem neuen Server `signing.key` ins Datenverzeichnis legen (sonst lehnen die Agenten neue Konfigurationen ab) und die Datei
  einmalig einspielen: `sitewatch serve -data … -import sitewatch-2026-11-01.json`. Das geht nur in eine Installation ohne Agenten; eine
  fehlerhafte Datei wird vollständig abgelehnt. Die Token der Agenten bleiben gültig, eine Änderung an den Agenten ist nicht nötig.

## Sites in Docker-Containern

Der Agent läuft auf dem **Host**, nicht im Container. Das Webroot ist dort per Bind-Mount lesbar (`composer.lock`, `var/logs`),
ebenso das Backup-Verzeichnis. Nur `composer`, `php` und bei Bedarf `nginx` und `mariadb` müssen im Container laufen. Dafür gibt
es Wrapper-Skripte in [`scripts/docker/`](scripts/docker):

| Skript | ersetzt | Compose-Service |
|---|---|---|
| `composer-in-docker`, `php-in-docker` | `composer`, `php` | `php` |
| `nginx-in-docker` | `nginx` | `nginx` |
| `mariadb-in-docker` | `mariadb` | `db` |

Das Paket `sitewatch-agent` installiert sie nach `/usr/share/sitewatch-agent/docker/`; in der `bootstrap.json` eintragen (beim Anlegen oder Erneuern eines Agenten im Dashboard kreuzt man an, welche Programme in Docker laufen; die anderen werden direkt auf dem Host aufgerufen)
(`composer`, `php`, `nginx`, `mariadb`). Sie finden den Container über die Compose-Labels und brauchen `SITE_DIR`, den absoluten Pfad
des Site-Verzeichnisses mit der `compose.yml`; er steht je Site in der Agentenkonfiguration (`env`). Das Arbeitsverzeichnis der
Site wird in den Container abgebildet. Die Wrapper sind bei den eigenen Sites erprobt, nicht allgemein getestet.

Hat eine Site keinen nginx oder keine Datenbank, ist das je Site einstellbar (`"nginx": false`, `"mariadb": false`); der Agent
meldet dann kein Problem. Was der Agent nicht ermitteln konnte, steht in der Detailansicht unter „Nicht ermittelt".

## Schnell ausprobieren (Demo)

```sh
./scripts/demo.sh          # baut, startet das Dashboard auf :8099 und lässt Demo-Agenten laufen
# Browser: http://127.0.0.1:8099
kill $(cat /tmp/sitewatch-demo/sitewatch.pid)
```

Die Demo startet ohne Login (`-no-login`) und nutzt Beispieldaten aus `testdata/` sowie einen **composer-Stub**. Nichts davon sind
echte Zahlen.

Gegen eine echte Site, ohne Server-Einrichtung:

```sh
go build -o bin/ ./cmd/...
bin/sitewatch serve -addr 127.0.0.1:8080 -no-login     # nur lokal; für den Betrieb OIDC einrichten
# Im Dashboard (http://127.0.0.1:8080/agents) einen Agenten anlegen: Typ „Contao-Bundle“ mit der Site-ID, oder einen
# Server-Agenten und die Site eintragen. Das Token erscheint einmalig, nur sein Hash wird gespeichert.
bin/agent -site-id meine-site -name "Meine Site" -kind contao -url https://example.org \
  -path /var/www/meine-site -sitewatch http://127.0.0.1:8080 -token "TOKEN-AUS-DEM-DASHBOARD" -once
```

Mit `-dry-run` gibt der Agent den Report nur aus, ohne zu senden. `-spool <dir>` puffert Reports, wenn das Dashboard nicht erreichbar ist.

## Selbst bauen

Voraussetzung ist eine aktuelle Go-Version (siehe `go.mod`).

```sh
go vet ./... && go test ./...
scripts/build.sh                          # Agent und Dashboard für linux/amd64, linux/arm64, darwin/arm64 nach bin/ (+ SHA256SUMS)
TARGETS="linux/amd64" scripts/build.sh    # nur ein Ziel
VERSION=0.1.0 scripts/build-deb.sh        # .deb-Pakete (nutzt nfpm über `go run`)
scripts/build-apt.sh                      # signiertes apt-Repository (braucht apt-ftparchive und einen GPG-Schlüssel)
```

`sitewatch -version` und `sitewatch-agent -version` zeigen die Version (aus `git describe`; `dev` ohne Build-Skript).

## Lizenz

GNU Affero General Public License, Version 3 (AGPL-3.0, siehe [`LICENSE`](LICENSE)). Wer Sitewatch verändert und als Dienst im Netz
anbietet, muss den geänderten Quelltext den Nutzern dieses Dienstes zugänglich machen. Schwachstellen bitte wie in
[`SECURITY.md`](SECURITY.md) melden.
