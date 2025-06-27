# detection_layer/session_logger.py

import psycopg2
from datetime import datetime
import json

# DB Setup
conn = psycopg2.connect(
    dbname="echidra_oss",
    user="postgres",
    password="murati@1234",
    host="localhost",
    port="5432"
)
cursor = conn.cursor()

def log_session(ip, protocol, data_dict):
    timestamp = datetime.utcnow().isoformat()
    cursor.execute("""
        INSERT INTO sessions (ip_address, protocol, data, timestamp)
        VALUES (%s, %s, %s, %s)
    """, (ip, protocol, json.dumps(data_dict), timestamp))
    conn.commit()
