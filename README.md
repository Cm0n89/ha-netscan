# NetScan — Home Assistant Add-on &nbsp;&nbsp;<img width="80" height="80" alt="NetScan icon" src="https://github.com/user-attachments/assets/6b851840-d09e-4c8d-91f8-eea68fb54329" />

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![HA Addon](https://img.shields.io/badge/Home%20Assistant-Add--on-blue?logo=homeassistant)](https://www.home-assistant.io/addons/)

A network scanner that runs directly inside Home Assistant. Displays all devices on your local network with IP address, MAC address, vendor, hostname, and device name.

<img width="1638" height="776" alt="NetScan screenshot" src="https://github.com/user-attachments/assets/a050da11-0bf0-4e2a-9941-cb75350250be" />

---

## Installation

1. Go to **Settings → Add-ons → Add-on Store**
2. Click the menu button ⋮ in the top right → **Repositories**
3. Add: `https://github.com/Cm0n89/ha-netscan`
4. Search for **NetScan** and install

---

## Features

- 🔍 **Automatic scanning** via nmap or built-in Python scanner
- 🏷️ **Device names** — auto-fetched from Shelly, Sonos, ESPHome, UPnP, Philips Hue and more
- 💬 **Comments** per device, linked to MAC address (survives rescans)
- 🟡🔴 **Offline tracking** with configurable threshold — yellow for recently offline, red for long-term offline
- ⟳ **Rescan** individual devices or remove them from the list
- 🌐 **English / Swedish** language toggle built into the UI
- 📱 **Mobile-friendly** interface via HA Ingress — no extra port needed

---

## Configuration

```yaml
scan_interval: 5        # Minutes between automatic scans
network: ""             # Leave empty for auto-detect, or set e.g. "192.168.68.0/22"
scan_method: nmap       # nmap (fastest), python, or auto
offline_threshold: 5    # Number of scans offline before red indicator
```

---

## Requirements

- Home Assistant OS or Supervised (running on Proxmox, Raspberry Pi, etc.)
- nmap is installed automatically inside the Docker container
- `host_network: true` is required to see the full network — configured automatically

---

## Offline Tracking

| Indicator | Meaning |
|---|---|
| 🟢 Green | Device responded in the latest scan |
| 🟡 Yellow | Offline for 1–(threshold−1) scans |
| 🔴 Red | Offline for ≥ threshold scans |

When a device goes offline, action buttons appear:
- **⟳** — ping the device immediately and restore status if it responds
- **✕** — remove the device from the list (shown when red)

---

## License

MIT — free to use and modify.

---

## Buy Me a Coffee

If you find this useful, a coffee is always appreciated! ☕

<img width="150" height="150" alt="Buy Me a Coffee QR code" src="https://github.com/user-attachments/assets/6b851840-d09e-4c8d-91f8-eea68fb54329" />
