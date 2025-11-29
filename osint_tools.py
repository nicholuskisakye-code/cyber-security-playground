
"""
osint_tools.py

Lightweight OSINT helpers:
- whois_query(domain): query a whois server and return text (simple, may be truncated)
- fetch_headers(host, port=80, secure=False): open a socket and request headers (minimal, no TLS fetch)
These are minimal implementations intended for local/learning use.
"""
import socket

def whois_query(domain: str, server: str = "whois.iana.org", timeout: float = 4.0) -> str:
    try:
        s = socket.create_connection((server, 43), timeout=timeout)
        s.sendall((domain + "\r\n").encode())
        resp = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        try:
            return resp.decode('utf-8', errors='ignore')
        finally:
            s.close()
    except Exception as e:
        return f"whois failed: {e}"

def fetch_headers(host: str, port: int = 80, path: str = "/", timeout: float = 4.0) -> str:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        req = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        resp = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        return resp.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"fetch_headers failed: {e}"
