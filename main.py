import os
# Point to the exact location of the manuf file on your system
os.environ["SCAPY_MANUF_PATH"] = "C:\\Program Files\\Wireshark\\manuf"

import asyncio
import websockets
import json
from scapy.all import sniff
import threading

# List to store active WebSocket connections
connections = []

async def handler(websocket, path):
    global connections
    connections.append(websocket)
    try:
        await websocket.wait_closed()
    finally:
        connections.remove(websocket)

async def broadcast(message):
    global connections
    # Convert message to JSON string
    message_json = json.dumps(message)
    # Send message to all active connections
    if connections:  # Check if there are any connections
        await asyncio.wait([ws.send(message_json) for ws in connections])

# The rest of your server and sniffing setup follows


# Modify start_server to avoid using asyncio.run which is not suitable for this case
def start_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    start_server_coro = websockets.serve(handler, "localhost", 8765)
    loop.run_until_complete(start_server_coro)
    loop.run_forever()

# Adjust the process_packet function to properly interact with asyncio from another thread
def process_packet(packet):
    src = packet.src
    dst = packet.dst
    t = packet.time
    smry = packet.summary()
    try:
        proto = packet.proto
    except AttributeError:
        proto = "ARP"
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
    # Ensure broadcast is called in a thread-safe manner
    if connections:
        # Correctly schedule broadcast to the right event loop
        loop = asyncio.get_event_loop()  # This needs to reference the event loop running your server
        asyncio.run_coroutine_threadsafe(broadcast(message), loop)

if __name__ == "__main__":
    # Initialize and run your server in a thread with a properly managed event loop
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Ensure there's an event loop for the main thread (if not already running)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Now, when `process_packet` attempts to schedule `broadcast`,
    # it correctly references an active event loop.