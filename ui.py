import tkinter as tk
from tkinter import ttk, Toplevel, Label, Text, END
from tkinter import messagebox
import sv_ttk

import threading
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse
import psutil
import time

import pandas as pd

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


class CollapsiblePane(Toplevel):
    def __init__(self, master, title="", *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.title(title)
        self.protocol("WM_DELETE_WINDOW", self.destroy)


# GUI application
class SnifferApp(tk.Tk):
    def __init__(self, interfaces):
        super().__init__()
        self.packets_dict = {}

        self.interfaces = interfaces
        self.sniff_thread = None
        self.stop_event = threading.Event()
        self.title("Packet Sniffer")

        self.listbox = tk.Listbox(self)
        self.update_interface_list()
        self.listbox.pack(fill=tk.BOTH, expand=True)
        
        self.start_button = tk.Button(self, text="Start", command=self.start)
        self.start_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.stop_button = tk.Button(self, text="Stop", command=self.stop)
        self.stop_button.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        # Frame for search/filter controls
        self.search_frame = tk.Frame(self)
        self.search_frame.pack(fill=tk.X, expand=True)

        self.search_label = tk.Label(self.search_frame, text="Search:")
        self.search_label.pack(side=tk.LEFT)

        self.search_entry = tk.Entry(self.search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<KeyRelease>", self.apply_filter)

        #----------------------------------------------------------------------------------

        self.columns = ('Time', 'Source', 'Destination', 'Protocol', 'Length', 'TCP Flags', 'Info')
        
        self.packet_table = ttk.Treeview(self, columns=self.columns, show='headings')
        
        # Create a dictionary to store the sort directions for each column
        self.sort_directions = {column: False for column in self.columns}

        for col in self.columns:
            heading_text = col
            if self.sort_directions[col]:
                heading_text += " ▼"  # Down arrow for descending sort
            else:
                heading_text += " ▲"  # Up arrow for ascending sort
            # Create the column headings with sorting functionality
            self.packet_table.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            self.packet_table.column(col, anchor=tk.CENTER)

        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.scroll_response)
        self.scrollbar.pack(side='right', fill='y')
        
        self.packet_table.config(yscrollcommand=self.scrollbar.set)
        self.packet_table.pack(side=tk.LEFT, expand=True, fill='both')  # Place the table on the left

        self.auto_scroll = True
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def sort_column(self, column):
        # Get the current sort direction for the column
        current_sort_direction = self.sort_directions[column]

        # Reverse the sort direction
        self.sort_directions[column] = not current_sort_direction
        # Update column headings with text icons
        for col in self.columns:
            heading_text = col
            if col == column:
                if self.sort_directions[col]:
                    heading_text += " ▼"  # Down arrow for descending sort
                else:
                    heading_text += " ▲"  # Up arrow for ascending sort
            self.packet_table.heading(col, text=heading_text)
        # Sort the table data based on the selected column
        sorted_data = sorted(self.packet_table.get_children(), key=lambda x: self.packet_table.set(x, column), reverse=current_sort_direction)

        # Rearrange the rows based on the sorted order
        for i, item in enumerate(sorted_data):
            self.packet_table.move(item, '', i)
    
    def apply_filter(self, event):
        search_term = self.search_entry.get().lower()
        for item in self.packet_table.get_children():
            values = [value.lower() for value in self.packet_table.item(item)['values']]
            if any(search_term in value for value in values):  # Partial Matching
                self.packet_table.reattach(item, '', 0) 
            else:
                self.packet_table.detach(item)  

    def clear_filter(self):
        self.search_entry.delete(0, tk.END)
        for item in self.packet_table.get_children():
            self.packet_table.reattach(item, '', 0)
            
    def clear_table(self):
        for item in self.packet_table.get_children():
            self.packet_table.delete(item)
        self.auto_scroll = True

    def update_interface_list(self):
        self.listbox.delete(0, tk.END)
        for iface_name, iface_details in self.interfaces.items():
            entry = f"{iface_name} - IPv4: {iface_details['IPv4']} IPv6: {iface_details['IPv6']}"
            self.listbox.insert(tk.END, entry)

    def scroll_response(self, *args):
        if args[0] == 'moveto':
            fraction = float(args[1])
            self.auto_scroll = fraction > 0.90
        elif args[0] == 'scroll':
            scroll_type, amount = args[1:]
            if scroll_type == "units":
                self.packet_table.yview_scroll(amount, "units")  
            elif scroll_type == 'pages':
                self.packet_table.yview_scroll(amount, "pages")  

        print("Scroll event args:", args)  # Keep this for debugging

        if args[0] != 'moveto':  # Protect the scrollbar.set() call
            self.scrollbar.set(*args) 

        if self.auto_scroll:
            self.packet_table.yview_moveto(1)

    def insert_packet(self, packet_data, packet):
        try:
            row_id = self.packet_table.insert("", 'end', values=packet_data)
            self.packets_dict[row_id] = packet
            self.packet_table.bind('<<TreeviewSelect>>', self.on_packet_select)
            row_color = get_row_color(packet)
            if row_color:
                self.packet_table.tag_configure(row_color, background=row_color)
                self.packet_table.item(row_id, tags=(row_color,))
            if self.auto_scroll:
                self.packet_table.see(row_id)  # Auto-scroll to new row
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        
    def start(self):
        self.start_button['state'] = 'disabled'  # Disable the start button
        self.stop_button['state'] = 'normal'    # Enable the stop button

        if self.sniff_thread is not None and self.sniff_thread.is_alive():
            messagebox.showwarning("Warning", "Sniffing is already running.")
            return
        
        # Clear existing table data
        self.clear_table()
        self.sort_directions = {column: False for column in self.columns}

        selection = self.listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select an interface.")
            return
        
        selected_interface = self.listbox.get(selection).split(" - ")[0]
        self.stop_event.clear()

        # Start sniffing
        self.sniff_thread = start_sniffing(selected_interface, self.packet_table, self.stop_event, self)

    def stop(self):
        self.start_button['state'] = 'normal'  # Re-enable the start button
        self.stop_button['state'] = 'disabled' # Disable the stop button
    
        if self.sniff_thread is not None:
            self.stop_event.set()

    def on_closing(self):
        if self.sniff_thread is not None:
            self.stop_event.set()
            self.sniff_thread.join()
        self.destroy()

    def show_packet_details(self, packet):
        def toggle_frame(f):
            f.pack_forget() if f.winfo_manager() else f.pack(fill="x", expand=True)
            
        details_window = CollapsiblePane(self, title="Packet Details")
        details_window.geometry("600x400")
        
        layer = packet
        layer_num = 0
        while layer:
            layer_num += 1
            frame = ttk.Frame(details_window)
            title = f"Layer {layer_num}: {layer.name}"
            btn = ttk.Button(frame, text=title, command=lambda f=frame: toggle_frame(f))
            btn.pack(fill="x", expand=True)
            content = Text(frame, wrap="word", height=5)
            for field_name in layer.fields:
                field_value = layer.sprintf(f"%{field_name}%")
                content.insert(END, f"{field_name}: {field_value}\n")
            content.pack(fill="x", expand=True)
            frame.pack(fill="x", expand=True)
            
            if layer.payload:
                layer = layer.payload
            else:
                break
        details_window.mainloop()

    def on_packet_select(self, event):
        selected_item = self.packet_table.selection()[0]  # Get the selected item ID
        packet = self.packets_dict.get(selected_item)  # Safely get the packet object
        if packet:
            self.show_packet_details(packet)  # Show the details if the packet is found


# Entry point for the GUI
if __name__ == "__main__":
    # Getting all network interfaces (virtual and physical)
    if_addrs = psutil.net_if_addrs()

    # Preparing a dictionary to map interface names to their details
    interfaces = {}

    # Iterating over interfaces
    for interface_name, interface_addresses in if_addrs.items():
        interfaces[interface_name] = {'IPv4': '', 'IPv6': ''}
        for address in interface_addresses:
            if str(address.family) == 'socket.AF_INET':
                interfaces[interface_name]['IPv4'] = address.address
            elif str(address.family) == 'socket.AF_INET6':
                interfaces[interface_name]['IPv6'] = address.address

    app = SnifferApp(interfaces)
    sv_ttk.set_theme("dark")
    app.mainloop()
