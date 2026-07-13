# NetScan Network Monitor

Network scanner built directly into Home Assistant.
Displays all devices on your network with IP, MAC, vendor, hostname and device name.

## Installation via GitHub (recommended)

1. Go to **Settings → Add-ons → Add-on Store**
2. Click ⋮ → **Repositories**
3. Add: `https://github.com/Cm0n89/ha-netscan`
4. Search for **NetScan** and install

## Configuration

| Option | Default | Description |
|---|---|---|
| `scan_interval` | 5 | Minutes between auto-scans |
| `network` | auto | E.g. `192.168.68.0/22` (empty = auto-detect) |
| `scan_method` | nmap | `nmap`, `python` or `auto` |
| `offline_threshold` | 5 | Scans offline before red indicator |

## Requirements

- Home Assistant OS or Supervised
- nmap is installed automatically inside the Docker container
- `host_network: true` is required to see the full network — configured automatically

## Troubleshooting

- **No devices shown**: Check that `network` is set correctly
- **nmap not finding devices**: Try switching to `scan_method: python`
- **Logs**: Settings → Add-ons → NetScan → Logs
