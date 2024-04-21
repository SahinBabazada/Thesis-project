import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QListWidget,
    QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit, QLabel,
    QMessageBox, QTextEdit, QDialog)

from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QColor
from PyQt5.QtGui import QColor, QFont

import psutil
import scapy
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, Raw
from scapy.arch.windows import get_windows_if_list
from scapy.layers.http import HTTPRequest, HTTPResponse
import time
import datetime
# from scapy.layers.inet import IP, TCP, UDP, ICMP

import joblib
from sklearn.preprocessing import StandardScaler, LabelEncoder
import numpy as np
import pandas as pd

from collections import defaultdict

# Global dictionary to keep track of packet sizes for each IP address
packet_sizes = defaultdict(list)

# Function to extract decimal value of TCP flags
def get_tcp_flags_decimal(tcp_flags):
    flag_dict = {
        'F': 1,  # FIN
        'S': 2,  # SYN
        'R': 4,  # RST
        'P': 8,  # PSH
        'A': 16, # ACK
        'U': 32, # URG
        'E': 64, # ECE
        'C': 128, # CWR
        'N': 256  # NS
    }
    decimal_flags = sum(flag_dict[flag] for flag in tcp_flags if flag in flag_dict)
    return decimal_flags



# Define color mappings
COLOR_MAPPINGS = {
    'TCP': QColor('#E6E6FA'),
    'UDP': QColor('#ADD8E6'),
    'HTTP': QColor('#90EE90'),
    'SYN': QColor('#A9A9A9'),
    'ACK': QColor('#A9A9A9'),
    'Errors': QColor('#FF0000'),  # Changed to Red for visibility
    'SMB': QColor('#FFFFE0'),
    'Routing': QColor('#DAA520')
}


import csv
def write_to_csv(data):
    with open('data_for_test.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(data)

def get_row_color(packet):
    if TCP in packet:
        if 'S' in packet[TCP].flags:
            return COLOR_MAPPINGS['SYN']
        elif 'A' in packet[TCP].flags and not 'S' in packet[TCP].flags:
            return COLOR_MAPPINGS['ACK']
        elif packet[TCP].dport == 80 or packet[TCP].sport == 80:
            return COLOR_MAPPINGS['HTTP']
        else:
            return COLOR_MAPPINGS['TCP']
    elif UDP in packet:
        return COLOR_MAPPINGS['UDP']
    return None  # Default no color

# Packet processing in a separate thread
class PacketSnifferThread(QThread):
    new_packet = pyqtSignal(object)
    packet_details = pyqtSignal(int, object)  # signal to send packet details
    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True
        self.packet_list = []  # list to store packets

    def run(self):
        sniff(iface=self.interface, prn=self.process_packet, stop_filter=self.stop_sniffing)

    def process_packet(self, packet):
        if self.running:
            self.packet_list.append(packet)  # store packet
            self.new_packet.emit(packet)  # emit signal with packet for display

    def stop_sniffing(self, packet):
        return not self.running

    def stop(self):
        self.running = False

# Dialog for displaying packet details
class PacketDetailsDialog(QDialog):
    def __init__(self, packet, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Details")
        self.setGeometry(100, 100, 600, 400)
        self.packet = packet
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Search functionality
        self.search_line_edit = QLineEdit(self)
        self.search_line_edit.setPlaceholderText("Search for fields...")
        self.search_line_edit.textChanged.connect(self.populate_tree)
        layout.addWidget(self.search_line_edit)
        
        # Tree display for packet details
        self.tree_widget = QTreeWidget(self)
        self.tree_widget.setHeaderLabel("Packet Layers")
        self.populate_tree()
        layout.addWidget(self.tree_widget)

        # Copy button
        copy_button = QPushButton("Copy Details", self)
        copy_button.clicked.connect(self.copy_details_to_clipboard)
        layout.addWidget(copy_button)

    def populate_tree(self):
        self.tree_widget.clear()  # Clear existing items
        search_text = self.search_line_edit.text().lower()
        layer = self.packet
        while layer:
            layer_name = f"{layer.name} Layer"
            # Create a top-level item for each layer
            layer_item = QTreeWidgetItem([layer_name])
            layer_item.setToolTip(0, layer_name)  # Set tooltip

            # Add fields as child items of the layer
            for field in layer.fields:
                field_value = f"{field}: {layer.fields[field]}"
                if search_text in field.lower() or search_text in str(layer.fields[field]).lower():
                    child_item = QTreeWidgetItem([field_value])
                    child_item.setToolTip(0, field_value)  # Set tooltip
                    layer_item.addChild(child_item)
            
            self.tree_widget.addTopLevelItem(layer_item)  # Add layer as a top-level item
            layer = layer.payload

    def copy_details_to_clipboard(self):
        details = []
        def recurse_items(item):
            details.append(item.text(0))
            for i in range(item.childCount()):
                recurse_items(item.child(i))

        for i in range(self.tree_widget.topLevelItemCount()):
            recurse_items(self.tree_widget.topLevelItem(i))

        clipboard_text = "\n".join(details)
        clipboard = QApplication.clipboard()
        clipboard.setText(clipboard_text)
        QMessageBox.information(self, "Copied", "Packet details copied to clipboard.")

# Main application window
class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.interfaces = self.create_interface_mapping()
        self.sniffer_thread = None
                # Load your model (ensure 'rf.joblib' is in the correct path)
        self.model = joblib.load('rf.joblib')
        self.scaler = StandardScaler()
        self.encoder = LabelEncoder()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Packet Sniffer')
        self.setGeometry(100, 100, 800, 600)
        self.setFont(QFont('Arial', 10))
        self.setStyleSheet("QWidget { background-color: #333; color: #EEE; }"
                           "QPushButton { background-color: #555; border: 1px solid #666; }"
                           "QPushButton:hover { background-color: #777; }"
                           "QLineEdit { border: 1px solid #666; }"
                           "QTreeWidget { border: none; }"
                           "QListWidget { border: none; }")

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()

        self.listbox = QListWidget()
        self.update_interface_list()
        main_layout.addWidget(self.listbox)

        self.start_button = QPushButton('Start')
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button = QPushButton('Stop')
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        main_layout.addLayout(button_layout)
        
        


        self.packet_table = QTreeWidget()  # Initialize packet table here
        self.packet_table.setHeaderLabels(['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        self.packet_table.itemDoubleClicked.connect(self.show_packet_details)  # Connect double-click to details view
        main_layout.addWidget(self.packet_table)
        
        central_widget.setLayout(main_layout)

    def create_interface_mapping(self):
        """ Return a mapping of interface friendly names to Scapy-compatible names """
        winList = get_windows_if_list()
        intfList = get_if_list()
        mapping = {}

        # Extract GUID from intfList and use it to map names from winList
        for intf in intfList:
            guid = intf.split('_')[-1][1:-1]  # Extract the GUID part from the interface name
            for win in winList:
                if win['guid'] == '{' + guid + '}':  # Check if GUIDs match
                    mapping[win['name']] = intf
                    break
        return mapping

    def update_interface_list(self):
        self.listbox.clear()
        for friendly_name, scapy_name in self.interfaces.items():
            self.listbox.addItem(f"{friendly_name} ({scapy_name})")

    def start_sniffing(self):
        selected = self.listbox.currentRow()
        if selected == -1:
            QMessageBox.warning(self, 'Warning', 'Please select an interface first.')
            return
        # Extract the Scapy-compatible name for sniffing
        selected_text = self.listbox.currentItem().text()
        scapy_name = selected_text.split('(')[-1][:-1]
        self.sniffer_thread = PacketSnifferThread(scapy_name)
        self.sniffer_thread.new_packet.connect(self.display_packet)
        self.sniffer_thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def display_packet(self, packet):
        timestamp = datetime.datetime.now()
        
        # Check if the packet has the IP layer
        if IP in packet:
            packet_size = len(packet)
            ttl = packet[IP].ttl
            proto = packet[IP].proto
            csum = packet[IP].chksum
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Default values
            src_port, dst_port, tcp_flags_decimal, type_icmp, code_icmp, csum_icmp, request_type = 0, 0, 0, 0, 0, 0, 0
            port_no = 0
        
            # Calculate RX and TX bytes average
            packet_sizes[src_ip].append(packet_size)
            packet_sizes[dst_ip].append(packet_size)
            rx_bytes_ave = sum(packet_sizes[dst_ip]) / len(packet_sizes[dst_ip])
            tx_bytes_ave = sum(packet_sizes[src_ip]) / len(packet_sizes[src_ip])

            if ICMP in packet:
                type_icmp = packet[ICMP].type
                code_icmp = packet[ICMP].code
                csum_icmp = packet[ICMP].chksum
                port_no = packet[ICMP].id
                request_type = 3
            elif TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                tcp_flags_decimal = get_tcp_flags_decimal(packet[TCP].flags)
                request_type = 1
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                request_type = 2

            data = {
                'timestamp': [timestamp], 
                'packet_size': [packet_size], 
                'ttl': [ttl], 
                'proto': [proto], 
                'csum': [csum], 
                'src_ip': [src_ip], 
                'dst_ip': [dst_ip], 
                'src_port': [src_port], 
                'dst_port': [dst_port], 
                'tcp_flag': [tcp_flags_decimal], 
                'type_icmp': [type_icmp], 
                'code_icmp': [code_icmp], 
                'csum_icmp': [csum_icmp], 
                'port_no': [port_no], 
                'rx_bytes_ave': [rx_bytes_ave], 
                'tx_bytes_ave': [tx_bytes_ave], 
                'request_type': [request_type],
                'id': [f'{dst_ip}{src_ip}{dst_port}{src_port}']
            }
            
            write_to_csv([i[0] for i in data.values()])
            df_test = pd.DataFrame(data)
        # Convert IP addresses to numerical format using a simple hash function
            df_test['src_ip'] = df_test['src_ip'].apply(hash)
            df_test['dst_ip'] = df_test['dst_ip'].apply(hash)
            df_test['id'] = df_test['id'].apply(hash)

            df_test.drop(['timestamp'], axis = 1, inplace = True)

            prediction = self.model.predict(df_test)
            
            # Log or use the prediction result
            if prediction[0] == 'malicious':
                print("Detected DoS!")
            elif prediction[0] == 'normal':
                print("Traffic is normal.")

        
        time_stamp = time.strftime('%H:%M:%S', time.localtime(packet.time))
        source = packet[IP].src if IP in packet else "-"
        destination = packet[IP].dst if IP in packet else "-"
        protocol = packet.sprintf("%IP.proto%")
        length = len(packet)
        info = f"{protocol}/{packet.dport}" if TCP in packet or UDP in packet else protocol
        item = QTreeWidgetItem([time_stamp, source, destination, protocol, str(length), info])
        color = get_row_color(packet)
        if color:
            for i in range(self.packet_table.columnCount()):
                item.setBackground(i, color)
        self.packet_table.addTopLevelItem(item)


    def apply_filter(self):
        search_term = self.search_entry.text().lower()
        for i in range(self.packet_table.topLevelItemCount()):
            item = self.packet_table.topLevelItem(i)
            match = any(search_term in item.text(col).lower() for col in range(item.columnCount()))
            item.setHidden(not match)

    def show_packet_details(self, item, column):
        index = self.packet_table.indexOfTopLevelItem(item)
        if index < len(self.sniffer_thread.packet_list):  # Check if index is within range
            packet = self.sniffer_thread.packet_list[index]  # Access the packet
            dialog = PacketDetailsDialog(packet, self)
            dialog.exec_()
        else:
            QMessageBox.warning(self, 'Error', 'Packet details could not be retrieved.')


# Start the application
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SnifferApp()
    ex.show()
    sys.exit(app.exec_())