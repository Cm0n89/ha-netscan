NetScan — Home Assistant Add-on
� �
Nätverksskanner som körs direkt i Home Assistant. Visar alla enheter på ditt lokala nätverk med IP-adress, MAC-adress, vendor, hostname och enhetsnamn.
�
Installation
Gå till Inställningar → Add-ons → Add-on Store
Klicka på menyknappen ⋮ uppe till höger → Repositories
Lägg till: https://github.com/Cm0n89/ha-netscan
Sök efter NetScan och installera
Funktioner
🔍 Automatisk scanning via nmap eller Python
🏷️ Enhetsnamn — Shelly, Sonos, ESPHome, UPnP, Philips Hue m.fl.
💬 Kommentarer per enhet (MAC-kopplat)
🟡🔴 Offline-spårning med konfigurerbart tröskelvärde
📱 Mobilvänligt gränssnitt via HA Ingress
Konfiguration
scan_interval: 5        # Minuter mellan auto-scanningar
network: ""             # Tomt = auto-detect, eller t.ex. "192.168.68.0/22"
scan_method: nmap       # nmap, python eller auto
offline_threshold: 5    # Scanningar offline innan röd indikering
Krav
Home Assistant OS eller Supervised
nmap installeras automatiskt
Licens
MIT — använd och modifiera fritt.
