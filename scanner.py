import tkintermapview
import ipaddress
import socket
import folium
import geocoder
import requests
from win32api import GetSystemMetrics as gsm
from customtkinter import *
from scapy.all import IP, TCP, sr1, ICMP, UDP
from scapy.layers.l2 import ARP, Ether, srp

#___________________________________________________________________________________________________
app = CTk()
app.title("Network Scanner")

width = gsm(0)
height = gsm(1)
app.geometry(f"{width-40}x{height-245}")

#___________________________________________________________________________________________________

     
def count_ip_addresses(ip_range):# count total number of ips in given network
    network = ipaddress.ip_network(ip_range, strict=False)
    total_ips = network.num_addresses
    return total_ips

def get_mac_address(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=1, verbose=0)[0]
    for sent, received in result:
        if received.psrc == ip:
            return received.hwsrc
    return None

def get_operating_system(target_ip):
    packet = IP(dst = target_ip) / TCP(dport = 80, flags = "S")
    response = sr1(packet, timeout=1)
    if response:
        if response.haslayer(TCP):
            if response[TCP].flags == 0x10: #ack flag
                return "Linux OS"
            elif response[TCP].flags == 0x04:# rst flag
                return "Window/Mac OS"
            else:
                print(f"Unexpected TCP flags for {target_ip}: {response[TCP].flags}")
        else:
            print(f"No TCP layer in response from {target_ip}.")
    else:
        print(f"No TCP response from {target_ip}. Trying ICMP...")

    packet = IP(dst=target_ip) / ICMP()
    response = sr1(packet, timeout=2)

    if response:
        ttl_value = response[IP].ttl
        if ttl_value == 128:
            return "Windows OS"
        elif ttl_value == 64:
            return "Linux OS"
        elif ttl_value == 255:
            return "macOS"
        else:
            print(f"Unknown TTL value for {target_ip}: {ttl_value}")
            return "Unknown OS"
    else:
        print(f"No ICMP response from {target_ip}.")
        return "Unknown OS"
    
    
def get_traceroute(destination_ip, max_hops = 30, timeout = 1):
    port = 33434
    ttl = 1
    while True:
        ip_packet = IP(dst = destination_ip, ttl=ttl)
        udp_packet = UDP(dport = port)
        packet = ip_packet / udp_packet
        reply = sr1(packet, verbose=0, timeout = timeout)
        ttl_list = []
        if reply is None:
            ttl_list.append(f"{ttl}\t*")
        elif reply.type == 3:
            ttl_list.append(f"{reply.src} (Dst Reached)")
            break
        else:
            ttl_list.append(str(reply.src))
    
        ttl += 1
        if ttl>max_hops:
            ttl_list.append("Max hops reached")
            break
    return ttl_list    

def get_open_ports(target_ip):
    open_ports = []
    for port in range(78, 82):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            result = s.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception as e:
            print(f"Error Scaning port {port} : {e}")
        finally:
            s.close()
    return open_ports    


        

def click_scan_button():
    ips = []
    mac_addrs = []
    os = []
    traceroutes = []
    open_ports = []
    network_info = {}
    
    ip_range = entry.get()
    network = ipaddress.ip_network(ip_range, strict=False)
    total_ips = count_ip_addresses(ip_range)
    print("total number of ips ", total_ips)
    response = requests.get(f"https://api.ipify.org/?format=json")
    data = response.json()
    public_ip = data.get("ip")
    print(public_ip)
    print(type(public_ip))
    
    g=geocoder.ip(public_ip)
    lat, long = g.latlng
    print("latitude : ", lat)
    print("longitude : ", long)
    
    map_widget.set_position(lat, long)
    #folium.Circle([lat, long], radius=50).add_to(map_widget)


    
   
    for ip in network:
        mac = get_mac_address(str(ip))
        ips.append(str(ip))
        mac_addrs.append(mac)
        operating_system = get_operating_system(str(ip))
        os.append(operating_system)
        tr = get_traceroute(str(ip))
        traceroutes.append(tr)
        op = get_open_ports(str(ip))
        open_ports.append(op)
        
        
        
    for i in range(len(ips)):
        print(f"IP: {ips[i]} => MAC: {mac_addrs[i]} => OS : {os[i]} => open ports : {open_ports[i]}")
        
    for i in range(len(ips)):
        label_ports = CTkLabel(sec2, text=", ".join(map(str, open_ports[i])) if open_ports[i] else "None")
        label_ip = CTkLabel(sec2, text=ips[i])
        label_mac = CTkLabel(sec2, text=mac_addrs[i] if mac_addrs[i] else "N/A")
        label_traceroute = CTkLabel(sec2, text=", ".join(traceroutes[i]) if traceroutes[i] else "No route")
        label_os = CTkLabel(sec2, text=os[i])
        label_ports.grid(row=i+1, column=0, padx=10, pady=5)
        label_ip.grid(row=i+1, column=1, padx=10, pady=5)
        label_mac.grid(row=i+1, column=2, padx=10, pady=5)
        label_traceroute.grid(row=i+1, column=3, padx=10, pady=5)
        label_os.grid(row=i+1, column=4, padx=10, pady=5)
        
    sec2.update_idletasks()




#___________________________________________________________________________________________________

# section 1 in which ip entry is done and scan button is included

sec1 = CTkFrame(master = app, 
                fg_color = "#8D6F3A", 
                border_color = "#FFCC70", 
                border_width = 2)

sec1.place(relx=0.0, 
           rely=0.0, 
           anchor='nw'
           , x=450, 
           y=20)


label = CTkLabel(
    sec1,
    text="Enter IP Range (e.g., 192.168.1.1/24):",
    text_color="#FFFFFF",  # White text color 
    font=("Arial", 14, "bold")  # Bold font 
)

entry = CTkEntry(
    sec1,
    placeholder_text="Enter IP address",
    fg_color="#FFFFFF",  # White background 
    text_color="#000000",  # Black text color
    border_color="#8D6F3A"
)

scan_button = CTkButton(
    sec1,
    text="SCAN",
    command=click_scan_button,
    fg_color="#FFCC70",  # Light yellow color 
    text_color="#000000",  # Black text color
    hover_color="#FFD700",  # Gold color on hover
    font=("Arial", 12, "bold")  # Bold font for the button
)

label.pack(pady=10, padx=10)
entry.pack(pady=10, padx=10)
scan_button.pack(pady=10, padx=10)

#__________________________________________________________________________________________________________

# sction 2 table of the output

sec2 = CTkScrollableFrame(master=app, 
                          fg_color = "#8D6F3A", 
                          border_color = "#FFCC70", 
                          border_width = 2, 
                          orientation="vertical", 
                          scrollbar_button_color='#FFCC70',
                          scrollbar_button_hover_color='#FFD700')

sec2.place(relx=0.0, 
           rely=0.0, 
           anchor='nw', 
           x=20, 
           y=sec1.winfo_height() + 30)


columns = ["Open Ports |", "IP Address |", "MAC Address |", "Traceroute IP's |", "OS"]

for col, head in enumerate(columns):
    
    label = CTkLabel(sec2, 
                     text=head, 
                     font = ("Arial", 12, "bold"))
    
    label.grid(row=0, column = col, padx=10, pady=5)
    
sec2.update_idletasks()
    
scan_result = []

for row, entry in enumerate(scan_result, start=1):
   for col, value in enumerate(entry):
      label = CTkLabel(sec2, text=value)
      label.grid(row=row, column=col, padx=20, pady=5)
      
      
sec2.update_idletasks()
sec2.configure(width=540, height=550)      

#________________________________________________________________________________________________________________

# section 3 map

sec3 = CTkFrame(master=app, 
                fg_color = "#8D6F3A", 
                border_color = "#FFCC70", 
                border_width = 2)

sec3.place(relx=0.0, 
           rely=0.0, 
           anchor='nw', 
           x=sec2.winfo_width() + 400, 
           y=sec1.winfo_height() + 30)

sec3.configure(width=620, height=565)  

map_widget = tkintermapview.TkinterMapView(sec3, 
                                           width=610, 
                                           height=570, 
                                           corner_radius=3)

map_widget.pack(expand=False)

map_widget.set_position(33.6612224, 73.0227223)  # Coordinates for Norway
map_widget.set_zoom(16)  # Set zoom level

#___________________________________________________________________________________________________________________

app.mainloop()