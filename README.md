
# Cyber Playground — Nemesis Edition

A local, safe cyber-security learning environment with neon hacker UI.

## Features
- Encryption lab (AES/RSA)
- Hashing (bcrypt, SHA-256)
- JWT creation/decoding
- Vulnerable SQLi demo (LOCAL ONLY) — intentionally insecure for learning
- Reflective XSS demo (LOCAL ONLY)
- Simple Port Scanner
- Metadata extractor (images)
- Neon-themed UI with multiple themes

## WARNING
This project is for **local learning only**. Do **NOT** run it exposed to the public internet. Some endpoints are intentionally vulnerable (SQLi, XSS) for educational reasons.

## Requirements
- Python 3.10+
- pip

## Install
```bash
python -m venv venv
source venv/bin/activate   # or venv\\Scripts\\activate on Windows
pip install -r requirements.txt
```

## Run
```bash
export FLASK_APP=app.py
export FLASK_ENV=development
python app.py
```
Open http://127.0.0.1:5000

## Notes
- Secret for JWT is `CYBER_PLAYGROUND_SECRET` env var.
- The vulnerable sqlite DB is in `playground/vuln.db` and has a seeded user: `admin` / `adminpass`.
- Use only on your machine or in an isolated VM.

## Docker (optional, recommended for isolation)

Build and run using docker-compose:

```bash
docker-compose build
docker-compose up
```

This exposes the app at http://127.0.0.1:5000 and runs the Flask app as a non-root user inside the container.

## New modules added
- `playground/packet_sniffer.py` — parse PCAP files or attempt a small live capture (requires permissions).
- `playground/osint_tools.py` — basic whois and header fetch helpers (socket-based).

Again, exercise caution and run the app in an isolated environment.
