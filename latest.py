import asyncio
import websockets
import json
from scapy.all import sniff, conf, get_if_list, IFACES
import psutil

import socket


# List to store active WebSocket connections
connections = []

hostname = socket.gethostname()

async def handler(websocket, path):
    # Add the WebSocket connection to the global list
    connections.append(websocket)
    try:
        # Keep the connection alive until it closes
        await websocket.wait_closed()
    finally:
        # Remove the connection from the list when it's closed
        connections.remove(websocket)

async def broadcast(message):
    # Convert message to JSON string
    message_json = json.dumps(message)
    # Send message to all active connections
    for websocket in connections:
        await websocket.send(message_json)

async def server():
    async with websockets.serve(handler, "localhost", 8765):
        await asyncio.Future()  # Run forever

def start_server():
    asyncio.run(server())

def process_packet(packet):
    src = packet.src
    dst = packet.dst
    t = packet.time
    smry = packet.summary()
    try:
        proto = packet.proto
    except AttributeError:
        proto = "ARP"

    # local_ip = socket.gethostbyname(hostname)

    length = len(packet)
    message = {
        "src": src,
        "dst": dst,
        "proto": proto,
        "time": t,
        "smry": smry,
        "length": length
    }
    print(message)
    # Broadcast the message to all connected clients
    asyncio.run(broadcast(message))

if __name__ == "__main__":
    # Start the WebSocket server in a separate thread
    from threading import Thread
    server_thread = Thread(target=start_server, daemon=True)
    server_thread.start()

    # Getting all network interfaces (virtual and physical)
    if_addrs = psutil.net_if_addrs()

    # Preparing a dictionary to map interface names to their details
    interfaces = {}

    # Iterating over interfaces
    for interface_name, interface_addresses in if_addrs.items():
        interfaces[interface_name] = {'IPv4': '', 'IPv6': ''}
        for address in interface_addresses:
            if str(address.family) == 'AddressFamily.AF_INET':
                # Storing IPv4 address
                interfaces[interface_name]['IPv4'] = address.address
            elif str(address.family) == 'AddressFamily.AF_INET6':
                # Storing IPv6 address
                interfaces[interface_name]['IPv6'] = address.address

    # Now you have a dictionary with interface names and their IP addresses
    for iface_name, iface_details in interfaces.items():
        print(f"Interface: {iface_name}, IPv4: {iface_details['IPv4']}, IPv6: {iface_details['IPv6']}")



    # Step 2: Present the list to the user for selection
    for idx, (interface_name, ipv4_address) in enumerate(interfaces.items(), start=1):
        print(f"{idx}: Interface: {interface_name}, IPv4 Address: {ipv4_address}")

    selection = int(input("Select an interface for packet sniffing (use the number): ")) - 1
    selected_interface = list(interfaces)[selection]

    # Step 3: Use the selected interface name to retrieve the system's internal name
    # (This step is platform-specific; on Windows, you might need a different approach.)
    # Assuming the system's internal name is the same as the interface name
    sniffing_interface = selected_interface

    print(sniffing_interface)

    sniff(iface=sniffing_interface, prn=process_packet, store=False)
