#!/usr/bin/env python3
"""
dns_reply.py – listen on UDP/53, print every query in human-readable form
and always answer with A=1.2.3.4 (TTL 60 s).
Usage:  sudo python3 dns_reply.py  [bind-ip]  [optional-fake-ip]
"""

import socket, struct, sys, datetime

DEF_ADDR   = "0.0.0.0"
DEF_ANSWER = "1.2.3.4"
DNS_PORT   = 53001

def labels_to_str(buf, offset):
    """Unpack DNS domain name (sequence of length-prefixed labels)."""
    parts, jumped = [], False
    original_offset = offset
    while True:
        if offset >= len(buf):
            break
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:                       # compression pointer
            if not jumped:
                original_offset = offset + 2
            offset = ((length & 0x3F) << 8) | buf[offset+1]
            jumped = True
            continue
        offset += 1
        parts.append(buf[offset:offset+length].decode('ascii'))
        offset += length
    return ".".join(parts), original_offset if jumped else offset

def build_reply(data, fake_ip):
    """Construct a minimal DNS reply with one A record pointing to fake_ip."""
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
    # We copy the question back unchanged
    question_end = 12
    while data[question_end] != 0:
        question_end += 1 + data[question_end] if data[question_end] & 0xC0 == 0 else 2
    question_end += 5   # zero-length label + QTYPE + QCLASS
    question = data[12:question_end]

    reply  = struct.pack('!HHHHHH', tx_id, 0x8180, qdcount, 1, 0, 0)
    reply += question
    # Answer RR: NAME (pointer), TYPE A, CLASS IN, TTL 60, RDLEN 4, RDATA
    reply += b'\xc0\x0c'                # pointer to question name
    reply += struct.pack('!HHIH', 1, 1, 60, 4)
    reply += socket.inet_aton(fake_ip)
    return reply

def main(bind_addr, answer_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_addr, DNS_PORT))
    print(f"[*] Listening on {bind_addr}:{DNS_PORT}, answering A with {answer_ip}")
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            if len(data) < 12:
                continue
            try:
                qname, _ = labels_to_str(data, 12)
                qtype, qclass = struct.unpack('!HH', data[-4:])
                print(f"{datetime.datetime.now():%H:%M:%S}  {addr[0]}:{addr[1]}  "
                      f"{qname}  IN  {qtype}  ({len(data)} bytes)")
            except Exception as e:
                print("malformed packet:", e)
            # send fixed reply
            sock.sendto(build_reply(data, answer_ip), addr)
    except KeyboardInterrupt:
        print("\n[!] shutting down")
    finally:
        sock.close()

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else DEF_ADDR,
         sys.argv[2] if len(sys.argv) > 2 else DEF_ANSWER)