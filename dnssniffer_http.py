#!/usr/bin/env python3
# doh_plain_53.py  – listen on TCP/53, DoH, always answers A=1.2.3.4
import socket, struct, datetime
from flask import Flask, request, make_response

app = Flask(__name__)

def build_reply(query: bytes, fake_ip: str) -> bytes:
    tx_id, flags, qdcount = struct.unpack('!HHH', query[:6])

    # copy header and fix flags / counts
    header = bytearray(query[:12])
    header[2:4] = struct.pack('!H', 0x8180)   # QR=1, RD=1, RA=1
    header[6:8] = struct.pack('!H', 1)        # ANCOUNT = 1

    # question section is everything up to the first zero-byte + 4 bytes (type+class)
    end_q = 12
    while query[end_q] != 0:
        if query[end_q] & 0xC0:               # compression pointer
            end_q += 2
            break
        end_q += 1 + query[end_q]
    if query[end_q] == 0:
        end_q +=1

@app.route('/dns-query', methods=['GET', 'POST'])
def dns_query():
    if request.method == 'GET':
        dns_bin = request.args.get('dns', '')
        if not dns_bin:
            return 'missing ?dns=', 400
        dns_bin = bytes.fromhex(dns_bin)
    else:  # POST
        dns_bin = request.get_data()
    print(datetime.datetime.now(), 'DoH query', len(dns_bin), 'bytes')
    resp = make_response(build_reply(dns_bin, '1.2.3.4'))
    resp.headers['Content-Type'] = 'application/dns-message'
    return resp

if __name__ == '__main__':
    # plain HTTP on TCP/53
    app.run('0.0.0.0', 53002, debug=False)