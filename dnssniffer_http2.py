#!/usr/bin/env python3
# doh_plain_53.py – minimal DNS-over-HTTPS server, plain HTTP on TCP/53
# always answers A=1.2.3.4, no EDNS, no error cases except FORMERR on garbage
import base64, binascii, datetime, socket, struct
from flask import Flask, request, make_response, abort

app = Flask(__name__)

# ------------------------------------------------------------------
def build_reply(query: bytes, fake_ip: str) -> bytes:
    """Return a valid DNS response (QR=1, RA=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0)"""
    if len(query) < 12:                          # too short -> FORMERR
        return b''

    tx_id, flags, qdcount = struct.unpack('!HHH', query[:6])
    if qdcount != 1:                             # we only support 1 question
        return b''

    # --- header ----------------------------------------------------
    header = bytearray(query[:12])
    header[2:4]  = struct.pack('!H', 0x8180)     # QR=1, RD=1, RA=1
    header[6:8]  = struct.pack('!H', 1)          # ANCOUNT = 1
    header[8:10] = struct.pack('!H', 0)          # NSCOUNT = 0
    header[10:12]= struct.pack('!H', 0)          # ARCOUNT = 0 (kdig happy)

    # --- question section ----------------------------------------
    end_q = 12
    try:
        while query[end_q] != 0:                 # read name
            if query[end_q] & 0xC0:              # compression pointer
                end_q += 2
                break
            end_q += 1 + query[end_q]
        if query[end_q] == 0:
            end_q += 1
        end_q += 4                               # skip QTYPE + QCLASS
        question = query[12:end_q]
    except (IndexError, struct.error):
        return b''

    # --- answer RR -----------------------------------------------
    answer = (
        b'\xc0\x0c'                              # name pointer
        + struct.pack('!HHIH', 1, 1, 60, 4)    # TYPE=A, CLASS=IN, TTL=60, RDLEN=4
        + socket.inet_aton(fake_ip)
    )
    return bytes(header) + question + answer
# ------------------------------------------------------------------

@app.route('/dns-query', methods=['GET', 'POST'])
def dns_query():
    if request.method == 'GET':
        # RFC 8484 §4.1  base64url encoded DNS message
        dns_b64 = request.args.get('dns', '')
        if not dns_b64:
            abort(400, 'missing ?dns=')
        try:
            dns_bin = base64.urlsafe_b64decode(dns_b64 + '==')  # pad if needed
        except binascii.Error:
            abort(400, 'bad base64')
    else:  # POST
        dns_bin = request.get_data()
        if not dns_bin:
            abort(400, 'empty body')

    print(datetime.datetime.now(), 'DoH query', len(dns_bin), 'bytes')
    reply = build_reply(dns_bin, '1.2.3.4')
    if not reply:
        abort(400, 'malformed DNS message')

    response = make_response(reply)
    response.headers['Content-Type'] = 'application/dns-message'
    return response

# ------------------------------------------------------------------
if __name__ == '__main__':
    # plain HTTP on TCP/53  (run: sudo python3 doh_plain_53.py)
    app.run(host='0.0.0.0', port=53002, debug=False)