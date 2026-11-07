# Changelog

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
