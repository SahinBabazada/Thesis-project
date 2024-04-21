import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QListWidget,
    QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLineEdit, QLabel,
    QMessageBox, QTextEdit, QDialog)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QColor, QFont

import psutil
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from scapy.arch.windows import get_windows_if_list
import time

# Define color mappings
COLOR_MAPPINGS = {
    'TCP': QColor('#E6E6FA'),
    'UDP': QColor('#ADD8E6'),
    'HTTP': QColor('#90EE90'),
    'SYN': QColor('#A9A9A9'),
    'ACK': QColor('#A9A9A9'),
    'Errors': QColor('#FF0000'),
    'SMB': QColor('#FFFFE0'),
    'Routing': QColor('#DAA520')
}

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
    return None

# Enhanced threading with packet list handling
class PacketSnifferThread(QThread):
    new_packet = pyqtSignal(object)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True
        self.packet_list = []

    def run(self):
        sniff(iface=self.interface, prn=self.process_packet, stop_filter=self.stop_sniffing)

    def process_packet(self, packet):
        if self.running:
            self.packet_list.append(packet)
            self.new_packet.emit(packet)

    def stop_sniffing(self, packet):
        return not self.running

    def stop(self):
        self.running = False

# Dialog for displaying packet details with improved UI
class PacketDetailsDialog(QDialog):
    def __init__(self, packet, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Packet Details")
        self.setGeometry(100, 100, 600, 400)
        self.packet = packet
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.search_line_edit = QLineEdit(self)
        self.search_line_edit.setPlaceholderText("Search for fields...")
        self.search_line_edit.textChanged.connect(self.populate_tree)
        layout.addWidget(self.search_line_edit)
        
        self.tree_widget = QTreeWidget(self)
        self.tree_widget.setHeaderLabel("Packet Layers")
        self.populate_tree()
        layout.addWidget(self.tree_widget)

        copy_button = QPushButton("Copy Details", self)
        copy_button.clicked.connect(self.copy_details_to_clipboard)
        layout.addWidget(copy_button)

    def populate_tree(self):
        self.tree_widget.clear()
        search_text = self.search_line_edit.text().lower()
        layer = self.packet
        while layer:
            layer_name = f"{layer.name} Layer"
            layer_item = QTreeWidgetItem([layer_name])
            layer_item.setToolTip(0, layer_name)
            for field in layer.fields:
                field_value = f"{field}: {layer.fields[field]}"
                if search_text in field.lower() or search_text in str(layer.fields[field]).lower():
                    child_item = QTreeWidgetItem([field_value])
                    child_item.setToolTip(0, field_value)
                    layer_item.addChild(child_item)
            self.tree_widget.addTopLevelItem(layer_item)
            layer = layer.payload

    def copy_details_to_clipboard(self):
        details = []
        def recurse_items(item):
            details.append(item.text(0))
            for i in range(item.childCount()):
                recurse_items(item.child(i))
        clipboard_text = "\n".join(details)
        clipboard = QApplication.clipboard()
        clipboard.setText(clipboard_text)
        QMessageBox.information(self, "Copied", "Packet details copied to clipboard.")

# Enhanced main window with better aesthetics
class SnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.interfaces = self.create_interface_mapping()
        self.sniffer_thread = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Packet Sniffer')
        self.setGeometry(100, 100, 1000, 600)  # Increased size for better layout
        self.setFont(QFont('Arial', 10))
        self.setStyleSheet("""
            QWidget { background-color: #333; color: #EEE; }
            QPushButton { background-color: #555; border: 1px solid #666; padding: 5px; }
            QPushButton:hover { background-color: #777; }
            QLineEdit { border: 1px solid #666; padding: 5px; }
            QTreeWidget { border: none; }
            QListWidget { border: none; }
        """)

        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.listbox = QListWidget()
        self.update_interface_list()
        main_layout.addWidget(self.listbox)

        button_layout = QHBoxLayout()
        self.start_button = QPushButton('Start')
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button = QPushButton('Stop')
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        main_layout.addLayout(button_layout)

        self.packet_table = QTreeWidget()
        self.packet_table.setHeaderLabels(['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        self.packet_table.itemDoubleClicked.connect(self.show_packet_details)
        main_layout.addWidget(self.packet_table)

    def create_interface_mapping(self):
        winList = get_windows_if_list()
        intfList = get_if_list()
        mapping = {}
        for intf in intfList:
            guid = intf.split('_')[-1][1:-1]
            for win in winList:
                if win['guid'] == '{' + guid + '}':
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

    def show_packet_details(self, item, column):
        index = self.packet_table.indexOfTopLevelItem(item)
        if index < len(self.sniffer_thread.packet_list):
            packet = self.sniffer_thread.packet_list[index]
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
