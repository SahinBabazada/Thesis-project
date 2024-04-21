import psutil
import sv_ttk
from classes import SnifferApp

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