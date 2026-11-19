# Changelog

## 1.0.21 — 2026-11-19

### Säkerhet
- Servern svarar nu bara på anrop som kommer via Home Assistant Ingress (172.30.32.2). Tidigare gick API:et att nå från hela nätverket på port 8099, utan inloggning. **Direktåtkomst på `http://<ha-ip>:8099` fungerar inte längre**, använd NetScan-panelen i HA.
- `network`-, `ip`- och `mac`-parametrar valideras innan de skickas till nmap/ping, så att man inte kan smyga in egna kommandoflaggor.
- CORS-headern `Access-Control-Allow-Origin: *` är borttagen.

### Nytt
- **Portskanning per enhet**: ny kolumn PORTAR med knappen ⌕ Skanna. Skannar cirka 70 vanliga portar (webb, SSH, SMB, MQTT, ESPHome, Modbus, Sonos, HA, Proxmox, Jellyfin, Plex m.fl.) med nmap och tjänsteidentifiering, eller med Python om nmap saknas.
- Resultatet visas i en utfällbar rad med produkt och version. Webbtjänster blir klickbara länkar.
- Resultaten sparas i `/data/ports.json` per MAC-adress och följer med i CSV-exporten (kolumnen `open_ports`).
- Nya endpoints: `GET /api/portscan/start?ip=&mac=`, `GET /api/portscan/status?ip=&mac=`, `GET /api/ports`.

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
