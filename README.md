# Phone OSINT

A desktop tool for **network scanning** and **phone number lookup** (OSINT), built with Python and CustomTkinter.

![Python](https://img.shields.io/badge/Python-3.8+-blue)  
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

### Network Scanner
- Scan an IP range (e.g. `192.168.1.0/24`)
- Detect **MAC address**, **OS** (Windows/Linux/macOS), **open ports**, **traceroute**
- Results in a scrollable table
- Map view showing your public IP location

### Phone Number Scanner
- Look up any phone number (with country code)
- **Owner / Caller ID** (CNAM; works best for US numbers via FreeCNAM)
- **Region**, **carrier**, **location**, **timezone**
- Number type (mobile, fixed line, VOIP, etc.)
- Validation and formats (National, International, E.164)

---

## Requirements

- **Windows** (uses `pywin32` for window sizing)
- Python 3.8+
- **Npcap** (for Network Scanner: MAC address, ARP, etc.) ? see below.

---

## Npcap (Windows) ? for Network Scanner

Scapy needs a packet capture driver. **WinPcap** is outdated; use **Npcap**:

1. Download **Npcap** (Windows):  
   https://npcap.com/#download  
   Use the installer that matches your Windows (e.g. `npcap-1.79.exe`).
2. Run the installer. Optionally check **"Install Npcap in WinPcap API-compatible Mode"** so Scapy can use it.
3. Restart the PC or at least restart the app after installing.
4. If you see *"No libpcap provider available"* when running `python scanner.py`, Npcap is not installed or not in use ? install or repair Npcap and try again.

Without Npcap, the app still runs but network scan (MAC, ARP) may fail or be limited.

---

## Installation

1. Clone or download this repo.
2. Create a virtual environment (optional but recommended):

   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   If you get an error for `tkintermapview`, use the version in `requirements.txt` (e.g. `tkintermapview>=1.29`).

---

## Usage

Run the app:

```bash
python scanner.py
```

- **Network Scanner** tab: enter IP range (e.g. `192.168.1.0/24`) and click **Scan network**.
- **Phone Number Scanner** tab: enter number (e.g. `+1234567890`) and optional default region (e.g. `US`), then click **Scan number**.

---

## Dependencies

| Package        | Purpose              |
|----------------|----------------------|
| customtkinter  | Modern GUI           |
| tkintermapview | Map widget           |
| scapy          | Network scan (ARP, etc.) |
| requests       | Public IP / HTTP     |
| geocoder       | IP geolocation       |
| phonenumbers   | Phone number lookup  |
| pywin32        | Windows (window size)|

---

## License

MIT.
