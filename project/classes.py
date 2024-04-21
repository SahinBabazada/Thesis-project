import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QListWidget, QPushButton, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem, QLabel, QLineEdit, QFrame, QScrollBar, QMessageBox
from PyQt5.QtCore import Qt, pyqtSignal, QThread, pyqtSlot, QObject
from functions import get_row_color, start_sniffing  # Ensure these are adapted for PyQt5

class PacketSnifferApp(QMainWindow):
    def __init__(self, interfaces):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.interfaces = interfaces
        self.init_ui()
        
    def init_ui(self):
        # Main layout
        self.main_layout = QVBoxLayout()
        
        # Interface list
        self.list_widget = QListWidget()
        self.update_interface_list()
        self.main_layout.addWidget(self.list_widget)
        
        # Start and Stop buttons
        self.start_button = QPushButton('Start')
        self.stop_button = QPushButton('Stop')
        self.stop_button.setEnabled(False)
        
        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        self.main_layout.addLayout(button_layout)
        
        # Packet Table
        self.packet_table = QTreeWidget()
        self.packet_table.setHeaderLabels(['Time', 'Source', 'Destination', 'Protocol', 'Length', 'TCP Flags', 'Info'])
        self.main_layout.addWidget(self.packet_table)
        
        # Setting up the central widget
        central_widget = QFrame()
        central_widget.setLayout(self.main_layout)
        self.setCentralWidget(central_widget)
        
    def update_interface_list(self):
        self.list_widget.clear()
        for iface_name, iface_details in self.interfaces.items():
            entry = f"{iface_name} - IPv4: {iface_details['IPv4']} IPv6: {iface_details['IPv6']}"
            self.list_widget.addItem(entry)
    
    def start(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        selected_interface = self.list_widget.currentItem()
        if selected_interface:
            iface_name = selected_interface.text().split(" - ")[0]
            # Assuming start_sniffing is adapted to PyQt5 and properly emits signals to update the UI
            self.sniffer_thread = start_sniffing(iface_name)
        else:
            QMessageBox.warning(self, "Warning", "Please select an interface.")

    def stop(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        # Signal to stop sniffing

    def closeEvent(self, event):
        # Clean up code to ensure threads are stopped
        event.accept()

app = QApplication(sys.argv)
interfaces = {'eth0': {'IPv4': '192.168.1.1', 'IPv6': 'fe80::1'}}
main_window = PacketSnifferApp(interfaces)
main_window.show()
sys.exit(app.exec_())
