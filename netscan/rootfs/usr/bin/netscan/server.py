#!/usr/bin/env python3
"""
NetScan Add-on Server — with HA Ingress support.
Reads NETSCAN_PORT from env (set by run.sh from ingress_port).
All API calls use relative URLs so they work under any ingress base path.
"""

import http.server
import socketserver
import os
import sys
import json
import threading
import subprocess
import socket
import re
import xml.etree.ElementTree as ET
import urllib.request as _ureq
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
PORT         = int(os.environ.get("NETSCAN_PORT", "8099"))
DATA_DIR           = os.environ.get("NETSCAN_DATA_DIR", "/data")
SCAN_INTERVAL      = int(os.environ.get("NETSCAN_SCAN_INTERVAL", "5"))
DEFAULT_NET        = os.environ.get("NETSCAN_NETWORK", "")
SCAN_METHOD        = os.environ.get("NETSCAN_METHOD", "auto")
OFFLINE_THRESHOLD  = int(os.environ.get("NETSCAN_OFFLINE_THRESHOLD", "5"))
STATIC_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

RESULTS_FILE  = os.path.join(DATA_DIR, "scan_results.json")
COMMENTS_FILE = os.path.join(DATA_DIR, "comments.json")
NMAP_XML      = os.path.join(DATA_DIR, "nmap_scan.xml")

os.makedirs(DATA_DIR, exist_ok=True)
print(f"[OK] Data dir  : {DATA_DIR}", flush=True)
print(f"[OK] Results   : {RESULTS_FILE}", flush=True)
print(f"[OK] Comments  : {COMMENTS_FILE}", flush=True)

# ── Scan state ─────────────────────────────────────────────────────────────────
_scan_lock    = threading.Lock()
_results_lock = threading.Lock()   # protects scan_results.json read/write
_scan_state = {"running": False, "progress": [],
               "started_at": None, "finished_at": None, "error": None}

# ─────────────────────────────────────────────────────────────────────────────
# Network helpers
# ─────────────────────────────────────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"

def detect_network(ip=None):
    if DEFAULT_NET: return DEFAULT_NET
    ip = ip or get_local_ip()
    return ip.rsplit(".", 1)[0] + ".0/24"

def find_nmap():
    for path in ["/usr/bin/nmap", "/usr/local/bin/nmap", "nmap"]:
        try:
            r = subprocess.run([path, "--version"], capture_output=True, timeout=3)
            if r.returncode == 0: return path
        except Exception: continue
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Device name fetching
# ─────────────────────────────────────────────────────────────────────────────
def _is_shelly_id(name):
    return bool(re.match(r'shelly[a-z0-9-]+-[0-9a-f]{6,12}$', name, re.IGNORECASE))

def _http_fetch(ip, path, port=80, timeout=2.5):
    try:
        req = _ureq.Request(f"http://{ip}:{port}{path}",
                            headers={"User-Agent": "NetScan/1.0", "Connection": "close"})
        with _ureq.urlopen(req, timeout=timeout) as r:
            return r.read(8192).decode("utf-8", errors="ignore"), dict(r.headers)
    except Exception:
        return "", {}

def _json_extract(body, *keys):
    try:
        val = json.loads(body)
        for k in keys:
            if not isinstance(val, dict): return ""
            val = val.get(k, "")
        return val.strip() if isinstance(val, str) else ""
    except Exception:
        return ""

def _xml_friendly_name(body):
    try:
        root = ET.fromstring(body)
        for el in root.iter('{urn:schemas-upnp-org:device-1-0}friendlyName'):
            if el.text and el.text.strip(): return el.text.strip()
        for el in root.iter('friendlyName'):
            if el.text and el.text.strip(): return el.text.strip()
    except Exception: pass
    m = re.search(r'<friendlyName>([^<]+)</friendlyName>', body)
    return m.group(1).strip() if m else ""

def _clean_sonos(name):
    name = re.sub(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*-\s*', '', name).strip()
    name = re.sub(r'\s*-\s*RINCON_[A-Z0-9]+.*$', '', name, flags=re.IGNORECASE).strip()
    return name

def fetch_device_name(ip):
    # Sonos port 1400
    try:
        with socket.create_connection((ip, 1400), timeout=0.8):
            body, _ = _http_fetch(ip, "/xml/device_description.xml", port=1400)
            if body:
                name = _xml_friendly_name(body)
                if name: return _clean_sonos(name)
    except Exception: pass

    # Port 80 check
    try:
        with socket.create_connection((ip, 80), timeout=0.8): pass
    except Exception:
        return ""

    # Shelly Gen1
    body, _ = _http_fetch(ip, "/settings")
    if body:
        name = _json_extract(body, "name")
        if name and not _is_shelly_id(name): return name

    # Shelly Gen2/Gen3
    for path in ["/rpc/Shelly.GetDeviceInfo", "/rpc/Shelly.GetConfig", "/rpc/Sys.GetConfig"]:
        body, _ = _http_fetch(ip, path)
        if body:
            name = (_json_extract(body, "name") or
                    _json_extract(body, "device", "name"))
            if name and not _is_shelly_id(name): return name

    # ESPHome
    body, hdrs = _http_fetch(ip, "/")
    server_hdr = hdrs.get("Server", hdrs.get("server", ""))
    if "esphome" in server_hdr.lower() or "esphome" in body[:2000].lower():
        m = re.search(r"<title[^>]*>(.+?)(?:\s*[–\-]+\s*ESPHome.*?)?</title>", body, re.IGNORECASE)
        if m:
            title = m.group(1).strip()
            if title.lower() not in {"esphome", ""} and len(title) > 1: return title

    # Generic UPnP
    for path in ["/xml/device_description.xml", "/device_description.xml", "/description.xml"]:
        b, _ = _http_fetch(ip, path)
        if b and "friendlyName" in b:
            name = _xml_friendly_name(b)
            if name: return _clean_sonos(name)

    # Philips Hue
    b, _ = _http_fetch(ip, "/api/config")
    if b:
        name = _json_extract(b, "name")
        if name and len(name) > 1: return name

    # Ubiquiti
    b, _ = _http_fetch(ip, "/api/v1/info")
    if b:
        name = _json_extract(b, "hostname")
        if name: return name

    # Generic HTML title
    if body:
        m = re.search(r"<title[^>]*>([^<]{2,80})</title>", body, re.IGNORECASE)
        if m:
            title = re.sub(r'\s*[-|]\s*(admin|router|login|home|web\s*ui).*$',
                           '', m.group(1), flags=re.IGNORECASE).strip()
            skip = {"router","login","home","index","welcome","untitled","web",
                    "page","admin","dashboard","status","shelly","switch","socket","esp"}
            if title.lower() not in skip and len(title) > 1: return title

    return ""

# ─────────────────────────────────────────────────────────────────────────────
# Scanning
# ─────────────────────────────────────────────────────────────────────────────
def _log(msg):
    print(msg, flush=True)
    with _scan_lock:
        _scan_state["progress"].append(msg)

def _write_results(network, devices):
    """Write scan results, preserving device_name, comments and tracking offline devices."""
    prev_by_mac = {}
    prev_by_ip  = {}
    offline_devices = []  # devices from previous scan not in current scan

    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE) as f:
                prev = json.load(f)
            for d in prev.get("devices", []):
                mac = d.get("mac", "")
                ip  = d.get("ip", "")
                if mac: prev_by_mac[mac] = d
                if ip:  prev_by_ip[ip]  = d
        except Exception as e:
            _log(f"[!] Could not read previous results: {e}")

    # Load comments
    saved_comments = {}
    if os.path.exists(COMMENTS_FILE):
        try:
            with open(COMMENTS_FILE) as f:
                saved_comments = json.load(f)
        except Exception:
            pass

    # Current scan IPs and MACs
    current_ips  = {d.get("ip")  for d in devices if d.get("ip")}
    current_macs = {d.get("mac") for d in devices if d.get("mac")}

    # Restore preserved fields for current devices
    for d in devices:
        mac = d.get("mac", "")
        ip  = d.get("ip", "")
        prev = prev_by_mac.get(mac) or prev_by_ip.get(ip) or {}

        if not d.get("device_name"):
            d["device_name"] = prev.get("device_name", "")
        d["comment"]       = saved_comments.get(mac, "")
        d["offline_count"] = 0
        d["last_seen"]     = datetime.now().isoformat()
        d["first_seen"]    = prev.get("first_seen", datetime.now().isoformat())

    # Find devices that were online before but missing now
    seen_keys = current_macs | current_ips
    for key, prev_d in {**prev_by_ip, **prev_by_mac}.items():
        mac = prev_d.get("mac", "")
        ip  = prev_d.get("ip", "")
        if mac in current_macs or ip in current_ips:
            continue  # still online
        # Skip if already added (mac+ip both in prev dicts)
        if any(o.get("ip") == ip for o in offline_devices):
            continue
        offline_count = prev_d.get("offline_count", 0) + 1
        offline_d = dict(prev_d)
        offline_d["offline_count"] = offline_count
        offline_d["comment"] = saved_comments.get(mac, prev_d.get("comment", ""))
        offline_devices.append(offline_d)
        _log(f"[~] Offline ({offline_count}x): {ip} {prev_d.get('device_name','')}")

    all_devices = devices + offline_devices

    with _results_lock:
        tmp = RESULTS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"scan_time":    datetime.now().isoformat(),
                       "network":      network,
                       "device_count": len(devices),
                       "devices":      all_devices,
                       "offline_threshold": OFFLINE_THRESHOLD},
                      f, indent=2, ensure_ascii=False)
        os.replace(tmp, RESULTS_FILE)

    _log(f"[OK] {len(devices)} online, {len(offline_devices)} offline tracked")

def run_nmap(network):
    nmap = find_nmap()
    if not nmap:
        with _scan_lock:
            _scan_state.update(running=False, finished_at=datetime.now().isoformat(),
                               error="nmap not found")
        return

    with _scan_lock:
        _scan_state.update(running=True, progress=[],
                           started_at=datetime.now().isoformat(), finished_at=None, error=None)

    _log(f"[*] nmap scan: {network}")
    cmd = [nmap, "-sn", "-T4", "--oX", NMAP_XML, network]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            line = line.rstrip()
            if line: _log(line)
        proc.wait()
        if proc.returncode != 0:
            raise RuntimeError(f"nmap exited {proc.returncode}")
    except Exception as e:
        with _scan_lock:
            _scan_state.update(running=False, finished_at=datetime.now().isoformat(), error=str(e))
        return

    devices = []
    try:
        tree = ET.parse(NMAP_XML)
        for host in tree.getroot().findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up": continue
            ip = mac = vendor = hostname = ""
            for addr in host.findall("address"):
                t = addr.get("addrtype", "")
                if t == "ipv4":
                    ip = addr.get("addr", "")
                elif t == "mac":
                    mac    = addr.get("addr", "").upper()
                    vendor = addr.get("vendor", "")
            hn = host.find("hostnames/hostname")
            if hn is not None: hostname = hn.get("name", "")
            if ip:
                devices.append({"ip": ip, "mac": mac, "vendor": vendor or "Unknown",
                                 "hostname": hostname, "device_name": ""})
    except Exception as e:
        _log(f"[!] XML parse error: {e}")

    _log(f"[+] Found {len(devices)} hosts")
    _write_results(network, devices)
    with _scan_lock:
        _scan_state.update(running=False, finished_at=datetime.now().isoformat())

def run_python_scan(network):
    import ipaddress, concurrent.futures
    with _scan_lock:
        _scan_state.update(running=True, progress=[],
                           started_at=datetime.now().isoformat(), finished_at=None, error=None)
    _log(f"[*] Python ping scan: {network}")
    try:
        hosts = list(ipaddress.ip_network(network, strict=False).hosts())
    except Exception as e:
        with _scan_lock:
            _scan_state.update(running=False, finished_at=datetime.now().isoformat(), error=str(e))
        return

    alive = []
    def ping(ip):
        r = subprocess.run(["ping", "-c", "1", "-W", "1", str(ip)], capture_output=True)
        if r.returncode == 0: alive.append(str(ip))

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        ex.map(ping, hosts)

    _log(f"[+] {len(alive)} hosts responded")
    arp = subprocess.run(["arp", "-n"], capture_output=True, text=True).stdout
    arp_map = {}
    for line in arp.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] != "(incomplete)":
            arp_map[parts[0]] = parts[2].upper()

    devices = [{"ip": ip, "mac": arp_map.get(ip, ""), "vendor": "Unknown",
                "hostname": "", "device_name": ""} for ip in sorted(alive)]
    _write_results(network, devices)
    with _scan_lock:
        _scan_state.update(running=False, finished_at=datetime.now().isoformat())

def start_scan(network, method="auto"):
    network = network or detect_network()
    use_nmap = (method == "nmap" or (method == "auto" and find_nmap()))
    t = threading.Thread(target=run_nmap if use_nmap else run_python_scan,
                         args=(network,), daemon=True)
    t.start()

def auto_scan_loop():
    import time; time.sleep(15)
    while True:
        with _scan_lock:
            running = _scan_state["running"]
        if not running:
            start_scan(detect_network(), SCAN_METHOD)
        time.sleep(SCAN_INTERVAL * 60)

# ─────────────────────────────────────────────────────────────────────────────
# HTTP Server — Ingress aware
# ─────────────────────────────────────────────────────────────────────────────
class ScanHandler(http.server.SimpleHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200); self._cors(); self.end_headers()

    def _strip_ingress(self, path):
        """Strip HA ingress prefix: /api/hassio_ingress/<token>/foo -> /foo"""
        m = re.match(r'^/api/hassio_ingress/[^/]+(/.*)?$', path)
        if m:
            return m.group(1) or "/"
        return path

    def do_GET(self):
        path = self._strip_ingress(self.path)
        p    = path.split("?")[0].rstrip("/") or "/"

        if   p in ("", "/", "/index.html"):  self._serve_static("index.html")
        elif p == "/api/scan_results":        self._serve_results()
        elif p == "/api/scan/status":         self._serve_status()
        elif p == "/api/scan/start":           self._serve_scan_start_get(path)
        elif p == "/api/scan/detect":         self._serve_detect()
        elif p == "/api/device_name":         self._serve_device_name(path)
        elif p == "/api/comments":            self._serve_comments()
        elif p == "/api/local_ip":            self._serve_local_ip()
        elif p == "/api/update_device":       self._serve_update_device_get(path)
        elif p == "/api/save_comment":         self._serve_save_comment_get(path)
        elif p == "/api/remove_device":        self._serve_remove_device(path)
        elif p == "/api/rescan_device":        self._serve_rescan_device(path)
        elif p == "/api/update_device":       self._serve_update_device()
        elif p.startswith("/static/"):        self._serve_static(p[8:])
        elif p in ("/favicon.ico",):
            self.send_response(204); self.end_headers()
        else:
            self._serve_static(p.lstrip("/"))

    def do_POST(self):
        path = self._strip_ingress(self.path)
        p    = path.split("?")[0]
        if   p == "/api/scan/start":       self._handle_scan_start()
        elif p == "/api/update_device":    self._handle_update_device()
        elif p == "/api/comments":         self._handle_save_comments()
        else:
            self.send_response(404); self.end_headers()

    # ── GET handlers ──────────────────────────────────────────────────────────
    def _serve_results(self):
        if not os.path.exists(RESULTS_FILE):
            self._json({"devices": []}); return
        mtime = os.path.getmtime(RESULTS_FILE)
        with open(RESULTS_FILE) as f: data = f.read()
        payload = data.encode()
        self.send_response(200); self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-cache")
        dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
        self.send_header("Last-Modified", dt.strftime("%a, %d %b %Y %H:%M:%S GMT"))
        self.end_headers(); self.wfile.write(payload)

    def _serve_status(self):
        with _scan_lock: self._json(dict(_scan_state))

    def _serve_save_comment_get(self, full_path):
        """GET /api/save_comment?mac=x&comment=y — saves comment to comments.json."""
        from urllib.parse import urlparse, parse_qs
        qs      = parse_qs(urlparse(full_path).query)
        mac     = qs.get("mac",     [""])[0].strip().upper()
        comment = qs.get("comment", [""])[0].strip()
        if not mac:
            self._json({"ok": False, "error": "missing mac"}); return
        try:
            with _results_lock:
                try:
                    with open(COMMENTS_FILE) as f:
                        comments = json.load(f)
                except Exception:
                    comments = {}
                if comment:
                    comments[mac] = comment
                elif mac in comments:
                    del comments[mac]
                tmp = COMMENTS_FILE + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(comments, f, indent=2, ensure_ascii=False)
                os.replace(tmp, COMMENTS_FILE)
            self._json({"ok": True})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _serve_remove_device(self, full_path):
        """GET /api/remove_device?ip=x — removes a device from scan_results.json."""
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(full_path).query)
        ip = qs.get("ip", [""])[0].strip()
        if not ip:
            self._json({"ok": False, "error": "missing ip"}); return
        try:
            with _results_lock:
                with open(RESULTS_FILE) as f:
                    data = json.load(f)
                data["devices"] = [d for d in data.get("devices", []) if d.get("ip") != ip]
                tmp = RESULTS_FILE + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                os.replace(tmp, RESULTS_FILE)
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] remove_device: {ip}", flush=True)
            self._json({"ok": True})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _serve_rescan_device(self, full_path):
        """GET /api/rescan_device?ip=x — pings a single IP and updates its status."""
        from urllib.parse import urlparse, parse_qs
        import subprocess as sp
        qs = parse_qs(urlparse(full_path).query)
        ip = qs.get("ip", [""])[0].strip()
        if not ip:
            self._json({"ok": False, "error": "missing ip"}); return
        try:
            r = sp.run(["ping", "-c", "2", "-W", "1", ip], capture_output=True)
            online = r.returncode == 0
            if online:
                # Reset offline_count in results file
                with _results_lock:
                    with open(RESULTS_FILE) as f:
                        data = json.load(f)
                    for d in data.get("devices", []):
                        if d.get("ip") == ip:
                            d["offline_count"] = 0
                            d["last_seen"] = datetime.now().isoformat()
                            break
                    tmp = RESULTS_FILE + ".tmp"
                    with open(tmp, "w") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    os.replace(tmp, RESULTS_FILE)
            self._json({"ok": True, "online": online})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    def _serve_scan_start_get(self, full_path):
        """GET /api/scan/start?network=x&method=y — starts a scan."""
        from urllib.parse import urlparse, parse_qs
        qs      = parse_qs(urlparse(full_path).query)
        network = qs.get("network", [""])[0].strip()
        method  = qs.get("method",  ["auto"])[0].strip()
        with _scan_lock:
            if _scan_state["running"]:
                self._json({"ok": False, "error": "Scan already running"}); return
        start_scan(network, method)
        self._json({"ok": True, "network": network or detect_network()})

    def _serve_detect(self):
        nmap = find_nmap()
        self._json({"available": nmap is not None, "path": nmap or ""})

    def _serve_device_name(self, full_path):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(full_path).query)
        ip = qs.get("ip", [""])[0].strip()
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] device_name << {ip}", flush=True)
        if not ip:
            self._json({"error": "missing ip", "name": ""}); return
        try:
            name = fetch_device_name(ip)
        except Exception as e:
            name = ""
            print(f"[{ts}] device_name error: {e}", flush=True)
        print(f"[{ts}] device_name >> {repr(name)}", flush=True)
        self._json({"ip": ip, "name": name})

    def _serve_comments(self):
        try:
            with open(COMMENTS_FILE) as f: data = f.read().encode()
        except Exception:
            data = b"{}"
        self.send_response(200); self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers(); self.wfile.write(data)

    def _serve_local_ip(self):
        ip  = get_local_ip()
        self._json({"local_ip": ip, "network": detect_network(ip)})

    def _serve_static(self, filename):
        if not filename or filename == "/": filename = "index.html"
        path = os.path.join(STATIC_DIR, filename)
        if not os.path.exists(path):
            self.send_response(404); self.end_headers(); return
        ext  = os.path.splitext(filename)[1]
        mime = {".html": "text/html", ".js": "application/javascript",
                ".css": "text/css", ".json": "application/json",
                ".svg": "image/svg+xml"}.get(ext, "application/octet-stream")
        with open(path, "rb") as f: data = f.read()
        self.send_response(200); self._cors()
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        # Prevent browser caching of HTML so updates take effect immediately
        if ext == ".html":
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
        self.end_headers(); self.wfile.write(data)

    # ── POST handlers ─────────────────────────────────────────────────────────
    def _serve_update_device_get(self, full_path):
        """GET /api/update_device?ip=x&device_name=y — saves device_name to scan_results.json."""
        from urllib.parse import urlparse, parse_qs
        ts  = datetime.now().strftime("%H:%M:%S")
        qs  = parse_qs(urlparse(full_path).query)
        ip  = qs.get("ip",          [""])[0].strip()
        name= qs.get("device_name", [""])[0].strip()

        if not ip:
            self._json({"ok": False, "error": "missing ip"}); return

        # Use file lock to prevent race conditions when multiple names saved simultaneously
        try:
            with _results_lock:
                if os.path.exists(RESULTS_FILE):
                    with open(RESULTS_FILE) as f:
                        data = json.load(f)
                else:
                    data = {"devices": []}

                updated = False
                for d in data.get("devices", []):
                    if d.get("ip") == ip:
                        if name:
                            d["device_name"] = name
                        updated = True
                        break

                if updated:
                    tmp = RESULTS_FILE + ".tmp"
                    with open(tmp, "w") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    os.replace(tmp, RESULTS_FILE)
                    print(f"[{ts}] update_device: {ip} -> {name}", flush=True)

            self._json({"ok": updated})
        except Exception as e:
            import traceback; traceback.print_exc()
            self._json({"ok": False, "error": str(e)})

    def _handle_update_device(self):
        """POST version — kept for compatibility but body is stripped by HA ingress."""
        self._json({"ok": False, "error": "Use GET with query params"})

    def _handle_scan_start(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b"{}"
        try:
            params  = json.loads(body)
            network = params.get("network", "")
            method  = params.get("method", "auto")
        except Exception:
            network, method = "", "auto"
        with _scan_lock:
            if _scan_state["running"]:
                self._json({"ok": False, "error": "Scan already running"}); return
        start_scan(network, method)
        self._json({"ok": True, "network": network or detect_network()})

    def _handle_save_comments(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(body)
            with open(COMMENTS_FILE, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self._json({"ok": True})
        except Exception as e:
            self._json({"ok": False, "error": str(e)})

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _json(self, data, status=200):
        payload = json.dumps(data).encode()
        self.send_response(status); self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers(); self.wfile.write(payload)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Ingress-Path")

    def log_message(self, fmt, *args):
        first = str(args[0]) if args else ""
        if any(k in first for k in ["scan", "device_name", "comments", "local_ip"]):
            ts   = datetime.now().strftime("%H:%M:%S")
            code = str(args[1]) if len(args) > 1 else "?"
            path = first.split()[1] if len(first.split()) > 1 else first
            print(f"[{ts}] {path} → {code}", flush=True)


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    os.makedirs(STATIC_DIR, exist_ok=True)
    print(flush=True)
    print(f"[OK] NetScan Add-on starting on port {PORT}", flush=True)
    print(f"[OK] Data dir  : {DATA_DIR}", flush=True)
    print(f"[OK] Network   : {detect_network()}", flush=True)
    print(f"[OK] Method    : {SCAN_METHOD}", flush=True)
    print(f"[OK] nmap      : {find_nmap() or 'not found'}", flush=True)
    print(flush=True)

    threading.Thread(target=auto_scan_loop, daemon=True).start()

    with ReusableTCPServer(("", PORT), ScanHandler) as httpd:
        print(f"[OK] Listening on port {PORT}", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[OK] Stopped.", flush=True)


if __name__ == "__main__":
    main()
