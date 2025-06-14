# Echidra – Multi-Protocol Honeypot


Modular honeypot built for realistic attacker interaction, log capture, and local analysis.

---

## 🔍 What is Echidra?

Echidra is a honeypot that simulates common network services to observe and record malicious behavior.  
It’s designed to be lightweight, extendable, and usable in real-world environments — not just demos.

## ✅ Core Features

- Emulates multiple protocols: SSH, FTP, HTTP, Telnet
- Captures full interaction sessions per IP
- Deception layer with fake files and trap commands
- Local alerts via SMTP or Webhooks
- Basic dashboard with GeoIP and timeline view
- PostgreSQL-based storage (JSON logs)
- Works with Docker or systemd

---

## 📐 Architecture

![image](https://github.com/user-attachments/assets/131186b0-f578-44a6-b268-d0d7150f85b5)




---

## 🧱 Tech Stack

| Component       | Stack                          |
|----------------|-------------------------------|
Core Runtime	|Python 3.11 (asyncio) – Honeypot core|
|Dashboard Frontend|	HTML + CSS + JavaScript + Chart.js|
|Dashboard Backend|	Node.js + Express|
|Storage	|PostgreSQL + JSONB|
|Deployment|	Docker Compose or systemd|
|Alerting|	SMTP + Webhooks (Discord/Slack)|
|Auth	|JWT + bcrypt (login/signup)|

---

## 📁 Folder Structure (Planned)

<pre>
```
Echidra/
├── capture_layer/ # Protocol emulators
├── deception_layer/ # Fake files, traps
├── detection_layer/ # Basic rules, rate-limits
├── correlation_engine/ # Session/IP grouping
├── alerts/ # Email + webhook alerts
├── dashboard/ # Web interface (Node.js)
├── db/ # PostgreSQL schema
├── scripts/ # Setup and deployment
├── docs/ # Architecture, setup notes
├── LICENSE
└── README.md
</pre>
  
---

## 🚀 Quick Start
```bash
git clone https://github.com/Qyleron/Echidra.git
cd Echidra
docker compose up

Visit http://localhost:8080 for the web interface.
Logs and captured data are stored in PostgreSQL for further analysis.


