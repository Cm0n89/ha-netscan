# NetScan Network Monitor

Nätverksskanner som körs direkt i Home Assistant och visar alla enheter på ditt lokala nätverk med IP-adress, MAC-adress, vendor, hostname och enhetsnamn.

## Funktioner

- **Automatisk scanning** via nmap eller inbyggd Python-scanner
- **Enhetsnamn** — hämta namn automatiskt från Shelly, Sonos, ESPHome och andra enheter
- **Kommentarer** — lägg till egna kommentarer per enhet (MAC-kopplat, överlever ny scanning)
- **Offline-spårning** — enheter som försvinner visas i gult och rött beroende på hur länge de varit offline
- **Inbyggt i HA** via Ingress — ingen extra port behövs
- **Mobilvänligt** gränssnitt

## Konfiguration

| Alternativ | Standard | Beskrivning |
|---|---|---|
| `scan_interval` | 5 | Minuter mellan automatiska scanningar |
| `network` | auto | Nätverkssegment, t.ex. `192.168.68.0/22`. Lämna tomt för auto-detect. |
| `scan_method` | nmap | `nmap` (snabbast), `python` eller `auto` |
| `offline_threshold` | 5 | Antal scanningar offline innan röd indikering |

## Användning

1. Starta add-on:et
2. Klicka på **NetScan** i sidopanelen
3. Klicka **⟳ SCANNA NU** för att starta en manuell scanning
4. Klicka **⟳ HÄMTA ALLA NAMN** för att hämta enhetsnamn för alla enheter

## Offline-indikering

- 🟢 **Grön** — enheten svarade i senaste scanning
- 🟡 **Gul** — offline 1–(threshold-1) scanningar
- 🔴 **Röd** — offline ≥ threshold scanningar

Vid offline visas knappar för att:
- **⟳** skanna om just den enheten
- **✕** ta bort enheten från listan (visas vid röd)

## Krav

- Home Assistant OS eller Supervised
- nmap installeras automatiskt inuti Docker-containern
- `host_network: true` krävs för att kunna se hela nätverket
