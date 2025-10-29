#!/usr/bin/env python3
# doh_real_53.py – DNS-over-HTTPS server, TCP/53, plain HTTP
# resolves names for real (A + AAAA) and returns genuine answers
import base64, binascii, datetime, socket, struct, dns.resolver   # pip install dnspython
from flask import Flask, request, make_response, abort

app = Flask(__name__)
RESOLVER = dns.resolver.Resolver()          # uses /etc/resolv.conf
RESOLVER.lifetime = 2                       # 2 s timeout per family

# ------------------------------------------------------------------
def qname_to_str(buf: bytes, offset: int) -> tuple[str, int]:
    parts, jumped = [], False
    original_offset = offset
    while True:
        if offset >= len(buf):
            break
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            if not jumped:
                original_offset = offset + 2
            offset = ((length & 0x3F) << 8) | buf[offset + 1]
            jumped = True
            continue
        offset += 1
        parts.append(buf[offset:offset + length].decode('ascii', errors='replace'))
        offset += length
    return ".".join(parts), original_offset if jumped else offset


def build_real_reply(query: bytes) -> bytes:
    """Return genuine DNS response (A + AAAA) or NXDOMAIN."""
    if len(query) < 12:
        return b''
    tx_id, _, qdcount = struct.unpack('!HHH', query[:6])
    if qdcount != 1:
        return b''

    # extract question name + type
    try:
        name, off = qname_to_str(query, 12)
        qtype, qclass = struct.unpack('!HH', query[off:off + 4])
        if qclass != 1:                # IN
            return b''
    except Exception:
        return b''

    # --- header skeleton ------------------------------------------
    header = bytearray(query[:12])
    header[2:4] = struct.pack('!H', 0x8180)      # QR=1, RD=1, RA=1
    header[6:8] = struct.pack('!H', 0)           # ANCOUNT (filled later)
    header[8:12] = struct.pack('!HH', 0, 0)      # NSCOUNT=0, ARCOUNT=0

    # --- question section ----------------------------------------
    question = query[12:off + 4]

    # --- resolve --------------------------------------------------
    answers = []
    rcode = 0                                    # 0 = NOERROR
    try:
        if qtype == 1:                           # A requested
            for rr in RESOLVER.resolve(name, 'A'):
                answers.append((1, socket.inet_aton(str(rr))))
        elif qtype == 28:                        # AAAA requested
            for rr in RESOLVER.resolve(name, 'AAAA'):
                answers.append((28, socket.inet_aton(str(rr))))
        else:                                    # we only support A/AAAA
            rcode = 4                            # NOTIMPL
    except dns.resolver.NXDOMAIN:
        rcode = 3                                # NXDOMAIN
    except Exception:                            # servfail / timeout
        rcode = 2                                # SERVFAIL

    # fix header flags and counts
    header[2:4] = struct.pack('!H', (0x8180 | (rcode & 0xF)))
    header[6:8] = struct.pack('!H', len(answers))

    # build answer section
    answer_bytes = b''
    for rrtype, rdata in answers:
        answer_bytes += (
            b'\xc0\x0c'                              # name pointer
            + struct.pack('!HHIH', rrtype, 1, 300, len(rdata))  # TTL 5 min
            + rdata
        )

    return bytes(header) + question + answer_bytes


# ------------------------------------------------------------------
@app.route('/dns-query', methods=['GET', 'POST'])
def dns_query():
    if request.method == 'GET':
        dns_b64 = request.args.get('dns', '')
        if not dns_b64:
            abort(400, 'missing ?dns=')
        try:
            dns_bin = base64.urlsafe_b64decode(dns_b64 + '==')
        except binascii.Error:
            abort(400, 'bad base64')
    else:  # POST
        dns_bin = request.get_data()
        if not dns_bin:
            abort(400, 'empty body')

    # ---- pretty console log -------------------------------------
    try:
        name, _ = qname_to_str(dns_bin, 12)
        qtype, = struct.unpack('!H', dns_bin[-4:-2])
        type_txt = {1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT'}.get(qtype, f'TYPE{qtype}')
        print(f"{datetime.datetime.now():%H:%M:%S}  query  {name}  IN  {type_txt}")
    except Exception as e:
        print(f"{datetime.datetime.now():%H:%M:%S}  query  <malformed>  ({e})")
    # --------------------------------------------------------------

    reply = build_real_reply(dns_bin)
    if not reply:
        abort(400, 'malformed DNS message')

    response = make_response(reply)
    response.headers['Content-Type'] = 'application/dns-message'
    return response


# ------------------------------------------------------------------
if __name__ == '__main__':
    # plain HTTP on TCP/53  (run: sudo python3 doh_real_53.py)
    app.run(host='0.0.0.0', port=53002, debug=False)