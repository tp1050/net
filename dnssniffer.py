#!/usr/bin/env python3
"""
dns_sniff.py – listen on UDP/53 and print every DNS query that arrives.
No replies are sent; the client will simply time-out.
Usage:  sudo python3 dns_sniff.py  [optional bind-ip, default 0.0.0.0]
"""

import socket
import binascii
import sys

DEF_ADDR = "0.0.0.0"
DNS_PORT = 5300
BUF_SIZE = 4096


def hexdump(data: bytes) -> str:
    """Return a classic 16-bytes-per-line hex + ASCII dump."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexpart:<48}  {ascpart}")
    return "\n".join(lines)


def main(bind_addr: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_addr, DNS_PORT))
    print(f"[*] Listening on {bind_addr}:{DNS_PORT} …")
    try:
        while True:
            data, addr = sock.recvfrom(BUF_SIZE)
            print(f"\n[+] Query from {addr[0]}:{addr[1]}  ({len(data)} bytes)")
            print(hexdump(data))
            # We deliberately do NOT send a reply
    except KeyboardInterrupt:
        print("\n[!] Caught Ctrl-C, shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEF_ADDR)