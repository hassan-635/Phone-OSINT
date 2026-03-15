"""
Phone OSINT Tool — Network Scanner & Phone Number Scanner
"""
import logging
import tkintermapview
import ipaddress
import socket
import threading
import phonenumbers
from phonenumbers import geocoder as pn_geocoder, carrier as pn_carrier, timezone as pn_timezone
from win32api import GetSystemMetrics as gsm
from customtkinter import *
from scapy.all import IP, TCP, sr1, ICMP, UDP, conf as scapy_conf
from scapy.layers.l2 import ARP, Ether, srp
import requests
import geocoder

# Suppress Scapy's verbose output and "MAC address not found" warnings in terminal
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
scapy_conf.verb = 0
import warnings
warnings.filterwarnings("ignore", message=".*MAC address.*")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = CTk()
app.title("Phone OSINT — Network & Number Scanner")

WIDTH = gsm(0)
HEIGHT = gsm(1)
app.geometry(f"{WIDTH - 40}x{HEIGHT - 120}")
app.minsize(1000, 600)

# Modern dark theme
set_appearance_mode("dark")
set_default_color_theme("blue")

# Color palette
COLORS = {
    "bg_dark": "#1a1b26",
    "bg_card": "#24283b",
    "accent": "#7aa2f7",
    "accent_hover": "#bb9af7",
    "success": "#9ece6a",
    "warning": "#e0af68",
    "error": "#f7768e",
    "text": "#c0caf5",
    "text_dim": "#565f89",
}

app.configure(fg_color=COLORS["bg_dark"])

# ---------------------------------------------------------------------------
# Phone number scanner logic
# ---------------------------------------------------------------------------
def get_caller_name(e164_number):
    """Try to get owner/caller name (CNAM). Works best for US numbers via FreeCNAM."""
    try:
        digits = "".join(c for c in e164_number if c.isdigit())
        if not digits:
            return None
        # FreeCNAM expects US 10-digit (no country code)
        if digits.startswith("1") and len(digits) == 11:
            q = digits[1:]
        elif len(digits) >= 10:
            q = digits[-10:] if len(digits) > 10 else digits
        else:
            q = digits
        r = requests.get("https://freecnam.org/dip", params={"q": q}, timeout=5)
        r.raise_for_status()
        name = (r.text or "").strip()
        if name and name.lower() not in ("", "unknown", "unavailable"):
            return name[:50]  # CNAM is typically 15 chars, allow a bit more
    except Exception:
        pass
    return None


def scan_phone_number(number_str, default_region="US"):
    """Look up phone number: region, carrier, timezone, validation, owner name."""
    result = {}
    try:
        parsed = phonenumbers.parse(number_str, default_region)
        result["valid"] = phonenumbers.is_valid_number(parsed)
        result["possible"] = phonenumbers.is_possible_number(parsed)
        result["format_national"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        result["format_international"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        result["format_e164"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        result["region"] = phonenumbers.region_code_for_number(parsed)
        result["number_type"] = phonenumbers.number_type(parsed)
        type_names = {
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed line",
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "Shared cost",
            phonenumbers.PhoneNumberType.VOIP: "VOIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
            phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
        }
        result["type_name"] = type_names.get(result["number_type"], "Unknown")
        try:
            result["location"] = pn_geocoder.description_for_number(parsed, "en") or "—"
        except Exception:
            result["location"] = "—"
        try:
            result["carrier"] = pn_carrier.name_for_number(parsed, "en") or "—"
        except Exception:
            result["carrier"] = "—"
        try:
            tz = pn_timezone.time_zones_for_number(parsed)
            result["timezone"] = ", ".join(tz) if tz else "—"
        except Exception:
            result["timezone"] = "—"
        # Owner / Caller ID (CNAM) - fetched separately, often US only
        result["owner_name"] = get_caller_name(result["format_e164"]) or "—"
        return result
    except phonenumbers.NumberParseException as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def run_phone_scan():
    num_input = phone_entry.get().strip()
    if not num_input:
        phone_status.configure(text="Enter a phone number (e.g. +1234567890)", text_color=COLORS["warning"])
        return
    phone_status.configure(text="Scanning…", text_color=COLORS["accent"])
    phone_results_frame.configure(state="normal")
    phone_results_frame.delete("1.0", "end")

    def do_scan():
        default_region = phone_region_entry.get().strip() or "US"
        info = scan_phone_number(num_input, default_region)
        app.after(0, lambda: show_phone_result(info))

    threading.Thread(target=do_scan, daemon=True).start()


def show_phone_result(info):
    phone_results_frame.configure(state="normal")
    phone_results_frame.delete("1.0", "end")
    if "error" in info:
        phone_status.configure(text="Error: " + info["error"], text_color=COLORS["error"])
        phone_results_frame.insert("end", f"Parse error: {info['error']}\n")
        return
    phone_status.configure(text="Scan complete", text_color=COLORS["success"])
    lines = [
        f"Owner / Caller ID:  {info.get('owner_name', '—')}",
        "",
        f"Valid:        {info['valid']}",
        f"Possible:     {info['possible']}",
        f"Type:         {info['type_name']}",
        f"Region:       {info['region']}",
        f"Location:     {info['location']}",
        f"Carrier:      {info['carrier']}",
        f"Timezone:     {info['timezone']}",
        "",
        f"National:     {info['format_national']}",
        f"International: {info['format_international']}",
        f"E.164:        {info['format_e164']}",
    ]
    phone_results_frame.insert("end", "\n".join(lines))


def clear_phone_results():
    phone_results_frame.configure(state="normal")
    phone_results_frame.delete("1.0", "end")
    phone_results_frame.insert("end", "Results will appear here after scanning.\nUse E.164 format (e.g. +1234567890) for best results.")
    phone_status.configure(text="Enter a number and click Scan number.", text_color=COLORS["text_dim"])


# ---------------------------------------------------------------------------
# Network scanner logic
# ---------------------------------------------------------------------------
def count_ip_addresses(ip_range):
    network = ipaddress.ip_network(ip_range, strict=False)
    return network.num_addresses


def get_mac_address(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=1, verbose=0)[0]
    for sent, received in result:
        if received.psrc == ip:
            return received.hwsrc
    return None


def get_operating_system(target_ip):
    packet = IP(dst=target_ip) / TCP(dport=80, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x10:
            return "Linux OS"
        elif response[TCP].flags == 0x04:
            return "Windows/Mac OS"
    packet = IP(dst=target_ip) / ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        ttl_value = response[IP].ttl
        if ttl_value == 128:
            return "Windows OS"
        elif ttl_value == 64:
            return "Linux OS"
        elif ttl_value == 255:
            return "macOS"
        return "Unknown OS"
    return "Unknown OS"


def get_traceroute(destination_ip, max_hops=30, timeout=1):
    port = 33434
    ttl = 1
    ttl_list = []
    while True:
        ip_packet = IP(dst=destination_ip, ttl=ttl)
        udp_packet = UDP(dport=port)
        packet = ip_packet / udp_packet
        reply = sr1(packet, verbose=0, timeout=timeout)
        if reply is None:
            ttl_list.append(f"{ttl}\t*")
        elif reply.type == 3:
            ttl_list.append(f"{reply.src} (Dst Reached)")
            break
        else:
            ttl_list.append(str(reply.src))
        ttl += 1
        if ttl > max_hops:
            ttl_list.append("Max hops reached")
            break
    return ttl_list


def get_open_ports(target_ip, ports_range=(78, 82)):
    open_ports = []
    for port in range(ports_range[0], ports_range[1]):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            if s.connect_ex((target_ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports


def clear_network_results():
    for w in network_table_children:
        try:
            w.destroy()
        except Exception:
            pass
    network_table_children.clear()
    network_status.configure(text="Results cleared. Enter IP range and scan.", text_color=COLORS["text_dim"])


def click_scan_button():
    ip_range = network_entry.get().strip()
    if not ip_range:
        network_status.configure(text="Enter an IP range (e.g. 192.168.1.0/24)", text_color=COLORS["warning"])
        return
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        network_status.configure(text="Invalid IP range.", text_color=COLORS["error"])
        return

    # Clear previous rows (keep header)
    clear_network_results()
    network_status.configure(text="Scanning network… (this may take a while)", text_color=COLORS["accent"])

    def do_scan():
        try:
            public_ip = None
            try:
                r = requests.get("https://api.ipify.org/?format=json", timeout=5)
                public_ip = r.json().get("ip")
            except Exception:
                pass
            if public_ip:
                g = geocoder.ip(public_ip)
                if g.latlng:
                    lat, lng = g.latlng
                    app.after(0, lambda: map_widget.set_position(lat, lng))
            ips, macs, os_list, traceroutes, open_ports = [], [], [], [], []
            for ip in list(network.hosts())[:50]:  # limit to first 50 hosts
                ip_str = str(ip)
                macs.append(get_mac_address(ip_str))
                ips.append(ip_str)
                os_list.append(get_operating_system(ip_str))
                traceroutes.append(get_traceroute(ip_str))
                open_ports.append(get_open_ports(ip_str))
            app.after(0, lambda: show_network_results(ips, macs, os_list, traceroutes, open_ports))
        except Exception as e:
            err_msg = str(e)
            app.after(0, lambda msg=err_msg: network_status.configure(text=f"Error: {msg}", text_color=COLORS["error"]))

    threading.Thread(target=do_scan, daemon=True).start()


def show_network_results(ips, mac_addrs, os_list, traceroutes, open_ports):
    network_status.configure(text=f"Found {len(ips)} host(s)", text_color=COLORS["success"])
    start_row = 1
    for i in range(len(ips)):
        r = start_row + i
        lab_ports = CTkLabel(network_sec, text=", ".join(map(str, open_ports[i])) if open_ports[i] else "—",
                             text_color=COLORS["text"], font=("Consolas", 11))
        lab_ip = CTkLabel(network_sec, text=ips[i], text_color=COLORS["text"], font=("Consolas", 11))
        lab_mac = CTkLabel(network_sec, text=mac_addrs[i] or "N/A", text_color=COLORS["text"], font=("Consolas", 11))
        lab_tr = CTkLabel(network_sec, text=", ".join(traceroutes[i][:3]) + ("…" if len(traceroutes[i]) > 3 else "") if traceroutes[i] else "—",
                          text_color=COLORS["text"], font=("Consolas", 10))
        lab_os = CTkLabel(network_sec, text=os_list[i], text_color=COLORS["text"], font=("Consolas", 11))
        for col, w in enumerate([lab_ports, lab_ip, lab_mac, lab_tr, lab_os]):
            w.grid(row=r, column=col, padx=8, pady=4, sticky="w")
        network_table_children.extend([lab_ports, lab_ip, lab_mac, lab_tr, lab_os])
    network_sec.update_idletasks()


# ---------------------------------------------------------------------------
# Main UI — Tabbed layout
# ---------------------------------------------------------------------------
tabview = CTkTabview(app, fg_color=COLORS["bg_card"], segmented_button_fg_color=COLORS["bg_dark"],
                     segmented_button_selected_color=COLORS["accent"], segmented_button_selected_hover_color=COLORS["accent_hover"],
                     text_color=COLORS["text"], corner_radius=10)
tabview.pack(fill="both", expand=True, padx=16, pady=16)
tabview.add("Network Scanner")
tabview.add("Phone Number Scanner")

# -------- Network Scanner tab --------
net_tab = tabview.tab("Network Scanner")
net_tab.configure(fg_color=COLORS["bg_dark"])

# Top: input card
net_input_frame = CTkFrame(net_tab, fg_color=COLORS["bg_card"], corner_radius=10, border_width=1, border_color=COLORS["text_dim"])
net_input_frame.pack(fill="x", padx=20, pady=(20, 12))

# Hint: Npcap needed for MAC/ARP scan on Windows
CTkLabel(net_input_frame, text="💡 For MAC/ARP scan install Npcap (WinPcap replacement). See README.",
         font=("Segoe UI", 10), text_color=COLORS["text_dim"]).pack(anchor="w", padx=16, pady=(8, 0))
CTkLabel(net_input_frame, text="IP range", font=("Segoe UI", 12, "bold"), text_color=COLORS["text"]).pack(anchor="w", padx=16, pady=(12, 4))
network_entry = CTkEntry(net_input_frame, placeholder_text="e.g. 192.168.1.0/24", height=36, font=("Consolas", 12),
                         fg_color=COLORS["bg_dark"], border_color=COLORS["accent"])
network_entry.pack(fill="x", padx=16, pady=(0, 12))

btn_frame = CTkFrame(net_input_frame, fg_color="transparent")
btn_frame.pack(fill="x", padx=16, pady=(0, 12))
scan_btn = CTkButton(btn_frame, text="Scan network", command=click_scan_button, fg_color=COLORS["accent"],
                     hover_color=COLORS["accent_hover"], height=36, font=("Segoe UI", 12, "bold"))
scan_btn.pack(side="left", padx=(0, 8))
CTkButton(btn_frame, text="Clear results", command=clear_network_results, fg_color=COLORS["text_dim"],
          hover_color=COLORS["error"], height=36).pack(side="left")

network_status = CTkLabel(net_tab, text="Enter IP range and click Scan.", font=("Segoe UI", 11), text_color=COLORS["text_dim"])
network_status.pack(anchor="w", padx=20, pady=(0, 8))

# Table + map row
content_frame = CTkFrame(net_tab, fg_color="transparent")
content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

network_sec = CTkScrollableFrame(content_frame, fg_color=COLORS["bg_card"], corner_radius=10, border_width=1, border_color=COLORS["text_dim"],
                                 scrollbar_button_color=COLORS["accent"], scrollbar_button_hover_color=COLORS["accent_hover"])
network_sec.pack(side="left", fill="both", expand=True, padx=(0, 12))
network_sec.configure(width=520, height=400)

network_table_children = []
headers_net = ["Ports", "IP", "MAC", "Traceroute", "OS"]
for c, h in enumerate(headers_net):
    CTkLabel(network_sec, text=h, font=("Segoe UI", 11, "bold"), text_color=COLORS["accent"]).grid(row=0, column=c, padx=8, pady=8, sticky="w")

map_frame = CTkFrame(content_frame, fg_color=COLORS["bg_card"], corner_radius=10, border_width=1, border_color=COLORS["text_dim"])
map_frame.pack(side="right", fill="both", expand=True)
map_frame.configure(width=420, height=400)
map_widget = tkintermapview.TkinterMapView(map_frame, width=410, height=390, corner_radius=8)
map_widget.pack(expand=True, fill="both", padx=4, pady=4)
map_widget.set_position(33.66, 73.02)
map_widget.set_zoom(10)

# -------- Phone Number Scanner tab --------
phone_tab = tabview.tab("Phone Number Scanner")
phone_tab.configure(fg_color=COLORS["bg_dark"])

phone_input_frame = CTkFrame(phone_tab, fg_color=COLORS["bg_card"], corner_radius=10, border_width=1, border_color=COLORS["text_dim"])
phone_input_frame.pack(fill="x", padx=20, pady=(20, 12))

CTkLabel(phone_input_frame, text="Phone number (with country code)", font=("Segoe UI", 12, "bold"), text_color=COLORS["text"]).pack(anchor="w", padx=16, pady=(12, 4))
phone_entry = CTkEntry(phone_input_frame, placeholder_text="e.g. +1 234 567 8900", height=36, font=("Consolas", 12),
                       fg_color=COLORS["bg_dark"], border_color=COLORS["accent"])
phone_entry.pack(fill="x", padx=16, pady=(0, 6))
CTkLabel(phone_input_frame, text="Default region (if no +code): e.g. US, GB", font=("Segoe UI", 10), text_color=COLORS["text_dim"]).pack(anchor="w", padx=16, pady=(0, 2))
phone_region_entry = CTkEntry(phone_input_frame, placeholder_text="US", height=32, width=80, font=("Consolas", 11),
                              fg_color=COLORS["bg_dark"], border_color=COLORS["text_dim"])
phone_region_entry.pack(anchor="w", padx=16, pady=(0, 12))
phone_btn_row = CTkFrame(phone_input_frame, fg_color="transparent")
phone_btn_row.pack(anchor="w", padx=16, pady=(0, 12))
CTkButton(phone_btn_row, text="Scan number", command=run_phone_scan, fg_color=COLORS["accent"],
          hover_color=COLORS["accent_hover"], height=36, font=("Segoe UI", 12, "bold")).pack(side="left", padx=(0, 8))
CTkButton(phone_btn_row, text="Clear", command=clear_phone_results, fg_color=COLORS["text_dim"],
          hover_color=COLORS["error"], height=36).pack(side="left")

phone_status = CTkLabel(phone_tab, text="Enter a number and click Scan number.", font=("Segoe UI", 11), text_color=COLORS["text_dim"])
phone_status.pack(anchor="w", padx=20, pady=(0, 8))

phone_results_frame = CTkTextbox(phone_tab, fg_color=COLORS["bg_card"], border_width=1, border_color=COLORS["text_dim"],
                                corner_radius=10, font=("Consolas", 12), text_color=COLORS["text"], wrap="word")
phone_results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
phone_results_frame.insert("end", "Results will appear here after scanning.\nUse E.164 format (e.g. +1234567890) for best results.")

# ---------------------------------------------------------------------------
app.mainloop()
