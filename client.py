# websocket_client.py
import asyncio
import websockets

async def listen(uri):
    async with websockets.connect(uri) as websocket:
        while True:
            message = await websocket.recv()
            print(f"< Received: {message}")

if __name__ == "__main__":
    uri = "ws://localhost:8765"
    print("Listening to the server...")
    asyncio.get_event_loop().run_until_complete(listen(uri))
