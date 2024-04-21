import tkinter as tk
from tkinter import ttk, messagebox
import sv_ttk

import threading
import socket
from scapy.all import sniff, IP, TCP, UDP
import psutil
import time
import socket


# Define color mappings for different protocols and states
COLOR_MAPPINGS = {
    'TCP': '#E6E6FA',
    'UDP': '#ADD8E6',
    'HTTP': '#90EE90',
    'SYN': '#A9A9A9',
    'ACK': '#A9A9A9',
}


def find_active_interface():
    """Find an active network interface with an IP address that is not a loopback address."""
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        for snic in interfaces[interface]:
            if snic.family == socket.AF_INET and not snic.address.startswith('127.'):
                return interface
    return None

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
    return None

def process_packet(packet, table, app):
    time_stamp = time.strftime('%H:%M:%S', time.localtime(packet.time))
    source = packet[IP].src if IP in packet else "-"
    destination = packet[IP].dst if IP in packet else "-"
    protocol = packet.sprintf("%IP.proto%")
    length = len(packet)
    flags = packet.sprintf("%TCP.flags%") if TCP in packet else "-"
    info = f"{protocol}/{packet.dport}" if TCP in packet or UDP in packet else protocol
    app.insert_packet((time_stamp, source, destination, protocol, length, flags, info), packet)

def find_active_interface():
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        for snic in interfaces[interface]:
            if snic.family == socket.AF_INET and not snic.address.startswith('127.'):
                return interface
    return None

class SnifferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Packet Sniffer")
        sv_ttk.set_theme("dark")

        self.columns = ('Time', 'Source', 'Destination', 'Protocol', 'Length', 'TCP Flags', 'Info')
        self.packet_table = ttk.Treeview(self, columns=self.columns, show='headings')
        for col in self.columns:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, anchor=tk.CENTER)
        self.packet_table.pack(side=tk.LEFT, expand=True, fill='both')
        
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.packet_table.yview)
        self.packet_table.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        self.start_button = ttk.Button(self, text="Start", command=self.start)
        self.start_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.stop_button = ttk.Button(self, text="Stop", command=self.stop)
        self.stop_button.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        self.stop_event = threading.Event()
        self.sniff_thread = None
        self.active_interface = find_active_interface()

    def insert_packet(self, packet_data, packet):
        row_id = self.packet_table.insert("", 'end', values=packet_data)
        row_color = get_row_color(packet)
        if row_color:
            self.packet_table.tag_configure(row_color, background=row_color)
            self.packet_table.item(row_id, tags=(row_color,))

    def start(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            messagebox.showwarning("Warning", "Sniffing is already running.")
            return

        if not self.active_interface:
            messagebox.showerror("Error", "No active network interface found.")
            return

        self.start_button['state'] = 'disabled'
        self.stop_button['state'] = 'normal'
        self.stop_event.clear()
        self.sniff_thread = threading.Thread(target=lambda: sniff(iface=self.active_interface, prn=lambda p: process_packet(p, self.packet_table, self), store=False, stop_filter=lambda x: self.stop_event.is_set()))
        self.sniff_thread.start()

    def stop(self):
        self.start_button['state'] = 'normal'
        self.stop_button['state'] = 'disabled'
        if self.sniff_thread:
            self.stop_event.set()

    def on_closing(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.stop_event.set()
            self.sniff_thread.join()
        self.destroy()

    def mainloop(self):
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        super().mainloop()

if __name__ == "__main__":
    app = SnifferApp()
    app.mainloop()
