# capture_layer/main.py
import asyncio
from datetime import datetime
import psycopg2
from detection_layer.session_logger import log_session
from dotenv import load_dotenv
import os

load_dotenv()


conn = psycopg2.connect(
    dbname=os.getenv("DB_NAME"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT")
)


cursor = conn.cursor()

def log_to_db(ip, port, service, message):
    timestamp = datetime.utcnow().isoformat()
    cursor.execute("""
        INSERT INTO interactions (ip, port, service, data, timestamp)
        VALUES (%s, %s, %s, %s, %s)
    """, (ip, port, service, message, timestamp))
    conn.commit()

# --- Honeypot Logic ---
async def handle_connection(reader, writer):
    addr = writer.get_extra_info('peername')
    ip, port = addr[0], addr[1]
    print(f"[+] Connection from {ip}:{port}")
    log_to_db(ip, port, "SSH", message or "No data")


    try:
        data = await reader.read(1024)
        message = data.decode(errors="ignore").strip() or "No data sent"
        log_to_db(ip, port, "SSH", message)
        writer.write(b"Unauthorized access\n")
        await writer.drain()
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        log_session(ip, "SSH", {"data": message or "No input"})
        writer.close()

async def main():
    server = await asyncio.start_server(handle_connection, '0.0.0.0', 2222)
    print("[*] SSH emulator running on port 2222")
    async with server:
        await server.serve_forever()

asyncio.run(main())

