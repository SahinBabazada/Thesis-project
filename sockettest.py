import asyncio
import websockets
import json
from scapy.all import sniff, conf, get_if_list, IFACES
import socket

# Define your filters here
ETHERNET_FILTER = ""  # Empty, since Ethernet captures everything
VBOX_INTERFACE = "vboxnet0"  # Example, adjust based on actual interface name
LOOPBACK_INTERFACE = "lo"  # or 'Loopback Pseudo-Interface 1' on Windows
LOCAL_AREA_CONNECTIONS = "eth0"  # Example, adjust based on actual interface names


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


    print(get_if_list())
    print(conf.ifaces)
    for iface in get_if_list():
        print(IFACES.data)
    # Start sniffing packets
    sniff(iface="\\Device\\NPF_{B36328B2-7FA3-46B1-852F-64CC448A8BFF}", prn=process_packet, store=False)