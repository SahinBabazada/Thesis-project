from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse
import time
import threading

# Define color mappings
COLOR_MAPPINGS = {
    'TCP': '#E6E6FA',
    'UDP': '#ADD8E6',
    'Errors': '#FF0000',  # Changed to Red for visibility
    'HTTP': '#90EE90',
    'SMB': '#FFFFE0',
    'Routing': '#DAA520',
    'SYN': '#A9A9A9',
    'ACK': '#A9A9A9',
}



# Function to get color based on packet details
def get_row_color(packet):
    if TCP in packet:
        if 'S' in packet[TCP].flags:
            return COLOR_MAPPINGS['SYN']
        elif 'A' in packet[TCP].flags and not 'S' in packet[TCP].flags:
            return COLOR_MAPPINGS['ACK']
        elif TCP in packet and packet[TCP].dport == 80 or packet[TCP].sport == 80:
            return COLOR_MAPPINGS['HTTP']
        else:
            return COLOR_MAPPINGS['TCP']
    elif UDP in packet:
        return COLOR_MAPPINGS['UDP']
    # Add other protocol checks and color assignments as needed
    return None  # Default no color

# Function to process packets and insert them into the GUI table
def process_packet(packet, table, app):
    # Extract packet details
    time_stamp = time.strftime('%H:%M:%S', time.localtime(packet.time))
    source = packet[IP].src if IP in packet else "-"
    destination = packet[IP].dst if IP in packet else "-"
    protocol = packet.sprintf("%IP.proto%")
    length = len(packet)
    flags = packet.sprintf("%TCP.flags%") if TCP in packet else "-"
    info = f"{protocol}/{packet.dport}" if TCP in packet or UDP in packet else protocol
    
    # Insert packet data into the table in a thread-safe manner
    app.insert_packet((time_stamp, source, destination, protocol, length, flags, info), packet)

# Function to start sniffing on a separate thread
def start_sniffing(interface, table, stop_event, app):
    def sniff_thread():
        sniff(iface=interface, prn=lambda p: process_packet(p, table, app), store=False, stop_filter=lambda x: stop_event.is_set()) 
    t = threading.Thread(target=sniff_thread)
    t.start()
    return t

