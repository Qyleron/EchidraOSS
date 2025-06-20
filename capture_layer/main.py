# capture_layer/main.py
import asyncio

async def handle_connection(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"[+] Connection from {addr}")
    writer.write(b"Fake Service\n")
    await writer.drain()
    writer.close()

async def main():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', 2222)
    print("[*] SSH emulator running on port 2222")
    async with server:
        await server.serve_forever()

asyncio.run(main())
