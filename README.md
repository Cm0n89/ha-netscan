# NetScan — Home Assistant Add-on                                                      <img width="100" height="100" alt="bmc_qr" src="https://github.com/user-attachments/assets/6b851840-d09e-4c8d-91f8-eea68fb54329" />

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![HA Addon](https://img.shields.io/badge/Home%20Assistant-Add--on-blue?logo=homeassistant)](https://www.home-assistant.io/addons/)

Nätverksskanner som körs direkt i Home Assistant. Visar alla enheter på ditt lokala nätverk med IP-adress, MAC-adress, vendor, hostname och enhetsnamn.

<img width="1638" height="776" alt="image" src="https://github.com/user-attachments/assets/a050da11-0bf0-4e2a-9941-cb75350250be" />

## Installation

1. Gå till **Inställningar → Add-ons → Add-on Store**
2. Klicka på menyknappen ⋮ uppe till höger → **Repositories**
3. Lägg till: `https://github.com/Cm0n89/ha-netscan`
4. Sök efter **NetScan** och installera

## Funktioner

- 🔍 **Automatisk scanning** via nmap eller Python
- 🏷️ **Enhetsnamn** — Shelly, Sonos, ESPHome, UPnP, Philips Hue m.fl.
- 💬 **Kommentarer** per enhet (MAC-kopplat)
- 🟡🔴 **Offline-spårning** med konfigurerbart tröskelvärde
- 📱 **Mobilvänligt** gränssnitt via HA Ingress

## Konfiguration

```yaml
scan_interval: 5        # Minuter mellan auto-scanningar
network: ""             # Tomt = auto-detect, eller t.ex. "192.168.68.0/22"
scan_method: nmap       # nmap, python eller auto
offline_threshold: 5    # Scanningar offline innan röd indikering
```
## Krav
- Home Assistant OS eller Supervised
- nmap installeras automatiskt
- 
## Licens
MIT — använd och modifiera fritt.

## BUYMEACOFFE
<img width="100" height="100" alt="bmc_qr" src="https://github.com/user-attachments/assets/6b851840-d09e-4c8d-91f8-eea68fb54329" />






