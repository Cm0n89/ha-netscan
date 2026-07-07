# NetScan — Home Assistant Add-on

Nätverksskanner som körs direkt i Home Assistant.
Visar alla enheter på nätverket med IP, MAC, vendor, hostname och enhetsnamn.

## Installation

### Alternativ 1: Lokal add-on (rekommenderas)

1. Kopiera mappen `netscan/` till `/addon_configs/` eller `/addons/` på din HA-instans
2. Gå till **Inställningar → Add-ons → Add-on store → ⋮ → Check for updates**
3. Du ska nu se "NetScan Network Monitor" under Lokala add-ons
4. Installera och starta

### Alternativ 2: Via Samba
Kopiera `netscan/`-mappen till `\\<ha-ip>\addons\` via Samba.

## Konfiguration

| Alternativ | Standard | Beskrivning |
|---|---|---|
| `scan_interval` | 5 | Minuter mellan auto-scans |
| `network` | auto | T.ex. `192.168.68.0/22` (tomt = auto) |
| `scan_method` | nmap | `nmap`, `python` eller `auto` |

## Åtkomst

Add-on:et körs på port **8080**.
Öppna: `http://<ha-ip>:8080`

Eller klicka på **Öppna webbgränssnitt** i add-on-panelen.

## Krav

- Home Assistant OS eller Supervised (kör på Proxmox = OK)
- nmap installeras automatiskt i Docker-containern
- `host_network: true` används för att kunna se hela nätverket

## Felsökning

- **Ser inga enheter**: Kontrollera att `network` är korrekt inställt
- **nmap hittar inte enheter**: Prova att byta till `scan_method: python`
- **Loggar**: Inställningar → Add-ons → NetScan → Loggar
