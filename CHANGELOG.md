# Changelog

## [1.8.1](https://github.com/cgoIT/sitewatch/compare/v1.8.0...v1.8.1) (2026-11-10)


### Bug Fixes

* **web:** Fehlertabellen brechen lange Meldungen um und scrollen nicht mehr horizontal ([5d16373](https://github.com/cgoIT/sitewatch/commit/5d16373568e6644a2dc7330f7898a13a11f1a9a0))

## [1.8.0](https://github.com/cgoIT/sitewatch/compare/v1.7.0...v1.8.0) (2026-11-10)


### Features

* Host-Aufträge (apt, Journal) und Auswertung der Stack-Logs ([6f39f5b](https://github.com/cgoIT/sitewatch/commit/6f39f5bc9cd477fe63a6155be5f8918d84ece371))
* Host-Aufträge (apt, Journal), Auswertung der Stack-Logs, Warnung bei vielen 5xx ([a4664c2](https://github.com/cgoIT/sitewatch/commit/a4664c22c28f088819bd00ed5fd537595951f4b2))
* Monitore per User-Agent aus den Zugriffen ausschließen, Warnung bei vielen 5xx ([4eb0d6f](https://github.com/cgoIT/sitewatch/commit/4eb0d6fb45b33299a81c398dd783d34a546a3acd))


### Bug Fixes

* 5xx-Anteil höchstens 100 %, Liste der User-Agents bei älterem Formular erhalten ([fd0755c](https://github.com/cgoIT/sitewatch/commit/fd0755cddacebb49b5cd91cee840958304266e09))

## [1.7.0](https://github.com/cgoIT/sitewatch/compare/v1.6.0...v1.7.0) (2026-11-09)


### Features

* NVMe-Verschleiß und Schreibvolumen erfassen, bewerten und anzeigen ([b362cde](https://github.com/cgoIT/sitewatch/commit/b362cde1f60e91e697993ee42c08e9d23b909986))
* **report:** NVMe-Verschleiß, Reserve und Schreibvolumen im Report (wear_pct, spare_pct, written_bytes) ([b1fa0ab](https://github.com/cgoIT/sitewatch/commit/b1fa0ab39cbd58547fae9c69e98dce8485842fde))
* **status:** Bewertung von NVMe-Verschleiß und Reserve, Schwellen in den Einstellungen ([9b1fb84](https://github.com/cgoIT/sitewatch/commit/9b1fb84b0e75f414a76ab4ab6bf5dbcb73d99680))
* **store:** Verlauf von Verschleiß und Schreibvolumen je Platte (disk_wear) ([2d3ca68](https://github.com/cgoIT/sitewatch/commit/2d3ca68b6e0a6e0a3be2f2f5ff2d509deb08b074))
* **web:** Platten der Host-Detailseite als eigene Blöcke, laufender Tag fehlt bei Geschrieben pro Tag ([a9dcdf4](https://github.com/cgoIT/sitewatch/commit/a9dcdf4227782357c25992c0e006da63cd52e366))
* **web:** Verschleiß und Schreibvolumen auf der Detailseite samt Kurven je Platte ([9d2bdf0](https://github.com/cgoIT/sitewatch/commit/9d2bdf0c928b1a8956da98920b68427fa2dda73e))


### Bug Fixes

* **collect:** NVMe-Prozentwerte außerhalb 0..255 verwerfen statt den Report abzulehnen ([c090538](https://github.com/cgoIT/sitewatch/commit/c09053863bb0fcd9a17234a08fc38abb44e50d10))

## [1.6.0](https://github.com/cgoIT/sitewatch/compare/v1.5.0...v1.6.0) (2026-11-09)


### Features

* **report:** Seriennummer und Schlüssel je Platte ([758e9a0](https://github.com/cgoIT/sitewatch/commit/758e9a0031d5d5a9d4abb198dd6e44c9e9baed4e))
* **status:** Warnung erst bei Anstieg über die Kenntnisnahme ([68ad993](https://github.com/cgoIT/sitewatch/commit/68ad99389570fc37a3f34ee56845d9c889dfe24c))
* **store:** Kenntnisnahme defekter Sektoren (disk_acks) ([8d569d6](https://github.com/cgoIT/sitewatch/commit/8d569d693c00f999d166702b198be89604352ef6))
* **web:** Netzwerk und Platten der Host-Detailseite unter die OS-Updates, kleinere Schrift in der Update-Tabelle ([f23eeab](https://github.com/cgoIT/sitewatch/commit/f23eeabc45d7b0bee50b00431dd761ba7da6c01d))
* **web:** Platten auf der Host-Detailseite zur Kenntnis nehmen ([5094de6](https://github.com/cgoIT/sitewatch/commit/5094de6baa9c6f72f189a04c991f8124315444c5))
* **web:** Verlauf und Sites im Agent-Formular standardmäßig zugeklappt ([e8e4a25](https://github.com/cgoIT/sitewatch/commit/e8e4a25ad6f7b12c34c92fe5dac7d4e13809121e))

## [1.5.0](https://github.com/cgoIT/sitewatch/compare/v1.4.0...v1.5.0) (2026-11-09)


### Features

* **agents:** Agent in der Oberfläche umbenennen ([2ace639](https://github.com/cgoIT/sitewatch/commit/2ace639d4bd8b59571c1ee7f6f1fc0a73216a5a7))
* **web:** Sites im Agent-Formular als Akkordeon, kleinere Schrift für IP-Adressen ([6456017](https://github.com/cgoIT/sitewatch/commit/6456017fecbdf47e1c41fe2df10dcdb672ca526b))


### Bug Fixes

* **collect:** smartctl-Typ sat weiter übergeben; Tests für Umbenennen und IDN ergänzt ([804d0ad](https://github.com/cgoIT/sitewatch/commit/804d0ad4701bf42241861d54ad634d8a38cee4cc))
* **collect:** smartctl-Typ scsi/sat der Autoerkennung überlassen (Temperatur und Sektoren bei SATA-Platten) ([1913f72](https://github.com/cgoIT/sitewatch/commit/1913f725fa45bd8b9eb53289331770c74af212a0))
* **collect:** Temperatur 0 °C als unbekannt behandeln ([f4bd3c5](https://github.com/cgoIT/sitewatch/commit/f4bd3c5ea50f5fc5f2c95bedc9ba54514aa2545d))
* **probe:** Domains mit Umlauten (IDN) für TLS-Prüfung und Favicons in Punycode wandeln ([de8b57f](https://github.com/cgoIT/sitewatch/commit/de8b57fe07990fc4942ca3c46170aa7287b63778))

## [1.4.0](https://github.com/cgoIT/sitewatch/compare/v1.3.0...v1.4.0) (2026-11-09)


### Features

* **collect:** OS-Info, Netzwerk, apt-Updates und failed units erfassen ([7d0534c](https://github.com/cgoIT/sitewatch/commit/7d0534c1a22aadc7a03150166433c51fed31a66c))
* Host-Details (OS, Netzwerk, apt-Updates, systemd) ([e048248](https://github.com/cgoIT/sitewatch/commit/e04824864df94c1e9177671fce30af5939fef828))
* **report:** OS-, Netzwerk-, Update- und systemd-Felder für Host-Reports ([84fa403](https://github.com/cgoIT/sitewatch/commit/84fa4030c2defa6aa305a078da6b4d6afa50beb2))
* **status:** Bewertung von Sicherheitsupdates, Neustart und systemd-Units ([cea07a6](https://github.com/cgoIT/sitewatch/commit/cea07a611bc88a9a7483493c2add04fcdc1680cb))
* **web:** Host-Detailseite und apt-Updates in der Übersicht ([65fad85](https://github.com/cgoIT/sitewatch/commit/65fad856c937d93bcdb87ca133d1e28c9171645a))

## [1.3.0](https://github.com/cgoIT/sitewatch/compare/v1.2.0...v1.3.0) (2026-11-08)


### Features

* **host:** SMART- und RAID-Überwachung für Host-Agents ([aee8e40](https://github.com/cgoIT/sitewatch/commit/aee8e40c5bb8f6f25eaa028d27fcf1b8c2ea1528))
* SMART-/RAID-Überwachung für Host-Agents und Favicons ([b959a0d](https://github.com/cgoIT/sitewatch/commit/b959a0df9f159332c0341d4f8235026c5942d841))
* **web:** Favicon der Sites in der Übersicht ([732131f](https://github.com/cgoIT/sitewatch/commit/732131f9d5e0db3ef6130eaa2f0354ccb1a1b70d))

## [1.2.0](https://github.com/cgoIT/sitewatch/compare/v1.1.0...v1.2.0) (2026-11-08)


### Features

* **login:** gleitende Sitzung mit 30 Tagen und Höchstalter von 90 Tagen ([93b09bc](https://github.com/cgoIT/sitewatch/commit/93b09bc800b942dd0f325513e11323bc69645cad))
* **push:** Web-Push für Alarme auf Mobilgeräten ([09c045d](https://github.com/cgoIT/sitewatch/commit/09c045d3250e3c379f410227bc991306ff12b1c6))

## [1.1.0](https://github.com/cgoIT/sitewatch/compare/v1.0.0...v1.1.0) (2026-11-07)


### Features

* Hinweis bei Massenausfall, Ping-Modus in CLAUDE.md festgehalten ([60391b4](https://github.com/cgoIT/sitewatch/commit/60391b44f699465e41531ddf6875e4043c4ba86f))
* Ping-Modus (Erreichbarkeit und Antwortzeit) ([be05776](https://github.com/cgoIT/sitewatch/commit/be057760d50072d5b5aabf74ac79f2cf72985012))
* **web:** Übersicht auf drei Seiten, Hosts-Tabelle, TLS/Backup-Spalten, Verlauf mobil unten ([c49a8e7](https://github.com/cgoIT/sitewatch/commit/c49a8e74a994f772b30e983d6ab5e4d6a562f6cc))

## [1.0.0](https://github.com/cgoIT/sitewatch/compare/v0.6.1...v1.0.0) (2026-11-01)


### Features

* Ergebnisse von Weckruf und Zertifikatsprüfung anzeigen, Schemaversion der Datenbank mit Migrationen ([9e7ca4c](https://github.com/cgoIT/sitewatch/commit/9e7ca4c28d24f9e2dc062e30dca5fd29fb6eeada))


### Bug Fixes

* Migration liest die Version in der Transaktion, Prüffehler ohne interne Adressen anzeigen, weitere Tests ([56a075e](https://github.com/cgoIT/sitewatch/commit/56a075e73de7dbe6abe8ed8e66b4097ca47b1810))


### Miscellaneous Chores

* Version 1.0.0 ([5adec2e](https://github.com/cgoIT/sitewatch/commit/5adec2e31b27e284ff9b8e2f9b8fdef813b66f1d))

## [0.6.1](https://github.com/cgoIT/sitewatch/compare/v0.6.0...v0.6.1) (2026-11-01)


### Bug Fixes

* Sites ohne Rücksicht auf Groß-/Kleinschreibung sortieren, Sites eines Agenten alphabetisch anzeigen ([9fc7e23](https://github.com/cgoIT/sitewatch/commit/9fc7e2321ab3a3ba959fb680b668b9bea8cdbc0b))

## [0.6.0](https://github.com/cgoIT/sitewatch/compare/v0.5.0...v0.6.0) (2026-11-01)


### Features

* verwaiste Sites mit allen Daten entfernen ([53401e3](https://github.com/cgoIT/sitewatch/commit/53401e376e8bd69774c6dc32cb24f138625f4a9d))


### Bug Fixes

* Alarmzustand gelöschter Sites verwerfen, Löschen dokumentiert und genauer getestet ([032ab6c](https://github.com/cgoIT/sitewatch/commit/032ab6cad43869488889929c21769b4fe9a6d099))

## [0.5.0](https://github.com/cgoIT/sitewatch/compare/v0.4.1...v0.5.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* -tokens, -thresholds und -stale haben keine Wirkung mehr.

### Features

* Agent-Typ contao-bundle, Agenten und Einstellungen in der Datenbank ([5ef0aba](https://github.com/cgoIT/sitewatch/commit/5ef0aba36ac1933fc8f8793d566a15c9e67a4a2e))
* Konfiguration exportieren und mit -import in eine leere Installation einspielen ([521863c](https://github.com/cgoIT/sitewatch/commit/521863cc3b11f3a508702eaa87d8a949744d7931))
* Weckruf und TLS-Ablaufprüfung für Contao-Bundles von Sitewatch aus ([49bcd59](https://github.com/cgoIT/sitewatch/commit/49bcd598dda2bfbca0f741f6197cf3fe0ee180f4))


### Bug Fixes

* SSRF-Filter des Weckrufs erweitert, veraltetes Zertifikat-Ablaufdatum verworfen, Import ohne Teilzustand ([22191d9](https://github.com/cgoIT/sitewatch/commit/22191d9a5549edd4f4f3f640c0dafc81b2307770))
* Token-Hash-Prüfung ohne Zeichenvorrat (gitleaks-Fehlalarm), Fehlalarm vermerkt ([c24e08d](https://github.com/cgoIT/sitewatch/commit/c24e08dd45e8ad10cec82d8ca17ebd2e40b95eb8))

## [0.4.1](https://github.com/cgoIT/sitewatch/compare/v0.4.0...v0.4.1) (2026-10-31)


### Bug Fixes

* Mobile Darstellung, Verlaufsgrafiken passen auf die Breite, Fehlermeldungen brechen um ([e1ddeed](https://github.com/cgoIT/sitewatch/commit/e1ddeeda2785d98b58b0f64991f899fcf004f9b2))

## [0.4.0](https://github.com/cgoIT/sitewatch/compare/v0.3.0...v0.4.0) (2026-10-31)


### Features

* Icons für die Art der Site (Host, PHP, Contao) in der Übersicht ([acfe140](https://github.com/cgoIT/sitewatch/commit/acfe140d125acf37a702f075b41d722118f511ea))
* Mobile Darstellung, Tabellen als Karten auf schmalen Bildschirmen ([0557844](https://github.com/cgoIT/sitewatch/commit/0557844b4cd07bca15bab761cff1f7098dae37c5))
* Site-Konfiguration in Gruppen gegliedert, Knopf „Alle gemeldeten wählen“ ([8a19cc4](https://github.com/cgoIT/sitewatch/commit/8a19cc42ecc503b73d1de82f639954ad722a7cf0))


### Bug Fixes

* pattern der ID-Felder gültig unter dem v-Flag von Chrome. ([8a19cc4](https://github.com/cgoIT/sitewatch/commit/8a19cc42ecc503b73d1de82f639954ad722a7cf0))

## [0.3.0](https://github.com/cgoIT/sitewatch/compare/v0.2.2...v0.3.0) (2026-10-31)


### Features

* Testmail für die Alarmierung (Knopf und alert-test) ([b0c2495](https://github.com/cgoIT/sitewatch/commit/b0c2495247b798170ce5ad7b9a51ad6cad08399d))

## [0.2.2](https://github.com/cgoIT/sitewatch/compare/v0.2.1...v0.2.2) (2026-10-30)


### Bug Fixes

* Paket sitewatch-agent legt /etc/sitewatch-agent an (0700) ([6b3d183](https://github.com/cgoIT/sitewatch/commit/6b3d183e622203cec434bfca388b6502e14a7207))

## [0.2.1](https://github.com/cgoIT/sitewatch/compare/v0.2.0...v0.2.1) (2026-10-30)


### Bug Fixes

* apt-Signierschlüssel nur noch RSA (Ubuntu 24.04 lehnt ed25519 ab) ([42b7014](https://github.com/cgoIT/sitewatch/commit/42b7014c33e5861ef03a06bb91205c1d2b5b9c96))

## [0.2.0](https://github.com/cgoIT/sitewatch/compare/v0.1.0...v0.2.0) (2026-10-30)


### Features

* Umbenennung in Sitewatch, Debian-Pakete und apt-Repository ([4a90c75](https://github.com/cgoIT/sitewatch/commit/4a90c75a318b2df20647f951608179baa6942f43))

## Changelog
