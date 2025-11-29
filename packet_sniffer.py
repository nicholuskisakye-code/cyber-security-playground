
"""
packet_sniffer.py

Safe packet helper:
- parse_pcap(file_path): parses a pcap file (requires scapy if available)
- live_capture(limit=100): attempts a very small raw socket capture (may require root). It's implemented defensively:
    - if permissions denied, raises a clear exception
    - does not write raw packets to disk unless explicitly requested

Note: Running live capture in containers may require --net=host and CAP_NET_RAW; avoid running without understanding permissions.
"""
import os
from typing import List

def parse_pcap(file_path: str) -> List[dict]:
    """
    Parse a pcap file and return a summarized list of packets.
    This function will try to use scapy if available; otherwise it falls back to reading binary header info.
    """
    try:
        from scapy.all import rdpcap
        packets = rdpcap(file_path)
        out = []
        for p in packets[:200]:
            summary = {
                "summary": p.summary(),
                "repr": repr(p)
            }
            out.append(summary)
        return out
    except Exception as e:
        # fallback: return file size and basic info
        try:
            size = os.path.getsize(file_path)
        except Exception:
            size = None
        return [{"error": "scapy not installed or failed to parse pcap", "file_size": size, "detail": str(e)}]

def live_capture(limit: int = 10):
    """
    Very small live capture using raw socket. May require root. This returns a list of (src, dst, proto, len)
    """
    results = []
    try:
        import socket, struct
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.settimeout(0.5)
        for i in range(limit):
            try:
                raw, addr = s.recvfrom(65535)
                # minimal parse of Ethernet + IP header
                eth_proto = struct.unpack('!H', raw[12:14])[0]
                if eth_proto == 0x0800 and len(raw) >= 34:
                    # IPv4
                    src = ".".join(map(str, raw[26:30]))
                    dst = ".".join(map(str, raw[30:34]))
                    proto = raw[23]
                    results.append({"src": src, "dst": dst, "proto": proto, "len": len(raw)})
            except TimeoutError:
                continue
        return results
    except PermissionError as pe:
        raise PermissionError("Live capture requires elevated permissions (root/CAP_NET_RAW). Use parse_pcap instead.") from pe
    except Exception as e:
        return [{"error": "live capture unavailable", "detail": str(e)}]
