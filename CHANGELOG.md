# Changelog

## 1.0.20 — 2026-11-18

### Nytt
- **Exportera CSV**: ny knapp i verktygsfältet som laddar ner enhetslistan som CSV (status, IP, enhetsnamn, kommentar, vendor, hostname, MAC, offline-räknare, first/last seen)
- Exporten följer aktuell sökning, sorteras på IP och har UTF-8 BOM så att å/ä/ö visas rätt i Excel
- Svenskt språkval ger `;` som avgränsare (Excel med svensk locale), engelskt ger `,`
- Ny endpoint: `GET /api/export.csv?sep=;&q=sökord`

## 1.0.0 — 2026-07-07

### Initial release
- nmap och Python-scanning av lokalt nätverk
- Enhetsnamn-hämtning (Shelly Gen1/Gen2/Gen3, Sonos, ESPHome, UPnP, Philips Hue m.fl.)
- Kommentarer per enhet kopplade till MAC-adress
- Offline-spårning med gul/röd indikering
- Rescan och ta bort enstaka enheter
- Inbyggt i HA via Ingress
- Mobilvänligt gränssnitt
