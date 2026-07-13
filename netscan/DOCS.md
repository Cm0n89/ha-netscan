# NetScan Network Monitor

Network scanner built directly into Home Assistant. Displays all devices on your local network with IP address, MAC address, vendor, hostname and device name.

## Usage

1. Start the add-on
2. Click **NetScan** in the sidebar
3. Click **⟳ SCAN NOW** to start a manual scan
4. Click **⟳ FETCH ALL NAMES** to automatically fetch device names for all devices

## Configuration

| Option | Default | Description |
|---|---|---|
| `scan_interval` | 5 | Minutes between automatic scans |
| `network` | auto | Network segment, e.g. `192.168.68.0/22`. Leave empty for auto-detect. |
| `scan_method` | nmap | `nmap` (fastest), `python` or `auto` |
| `offline_threshold` | 5 | Number of scans offline before red indicator |

## Features

- **Automatic scanning** via nmap or built-in Python scanner
- **Device names** — auto-fetched from Shelly, Sonos, ESPHome, UPnP, Philips Hue and more
- **Comments** — add your own comments per device (linked to MAC address, survives rescans)
- **Offline tracking** — devices that disappear are shown in yellow and red depending on how long they have been offline
- **Built into HA** via Ingress — no extra port needed
- **English / Swedish** language toggle in the UI
- **Mobile-friendly** interface

## Offline indicators

| Indicator | Meaning |
|---|---|
| 🟢 Green | Device responded in the latest scan |
| 🟡 Yellow | Offline for 1–(threshold−1) scans |
| 🔴 Red | Offline for ≥ threshold scans |

When a device goes offline, action buttons appear:
- **⟳** — ping the device immediately and restore status if it responds
- **✕** — remove the device from the list (shown when red)

## Requirements

- Home Assistant OS or Supervised
- nmap is installed automatically inside the Docker container
- `host_network: true` is required to see the full network — configured automatically
