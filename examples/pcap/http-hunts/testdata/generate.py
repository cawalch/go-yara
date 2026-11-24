"""Rebuild the offline fixture using documentation IPs and fixed nanosecond times."""
from pathlib import Path
from struct import pack

capture = bytearray(pack("<IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, 65535, 101))
positions = {}
frame = 0


def checksum(data):
    data += bytes(len(data) % 2)
    n = sum(int.from_bytes(data[i:i+2], "big") for i in range(0, len(data), 2))
    while n >> 16:
        n = (n & 65535) + (n >> 16)
    return n ^ 65535


def packet(client, body, port=80, retransmit=False):
    global frame
    frame += 1
    src, dst = bytes([192, 0, 2, client]), bytes([198, 51, 100, 80])
    key = (client, port)
    seq = positions.get(key, 1)
    if retransmit:
        seq -= len(body)
    else:
        positions[key] = seq + len(body)
    tcp = pack("!HHIIBBHHH", 53000, port, seq, 1, 0x50, 0x18, 8192, 0, 0)
    check = checksum(src + dst + pack("!BBH", 0, 6, len(tcp) + len(body)) + tcp + body)
    tcp = tcp[:16] + pack("!H", check) + tcp[18:] + body
    ip = pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), frame, 0, 64, 6, 0) + src + dst
    wire = ip[:10] + pack("!H", checksum(ip)) + ip[12:] + tcp
    capture.extend(pack("<IIII", 1700000000, frame * 1234567, len(wire), len(wire)) + wire)


def request(method, host, path="/example"):
    return f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n".encode()


def h2(kind, flags, stream, data):
    return len(data).to_bytes(3, "big") + pack("!BBI", kind, flags, stream) + data


packet(10, request("GET", "app.example", "/health"))
post = request("POST", "WEBHOOK.SITE:80", "/sample-token?private=1")
packet(10, post[:2])
packet(10, post[2:])
packet(10, post[2:], retransmit=True)
packet(11, post)  # Approved integration.
packet(12, post)  # Workstation.
packet(10, request("POST", "webhook.site.example") + request("GET", "webhook.site"))
packet(13, request("GET", "app.example", "/unused-canary"))  # Approved scanner.
packet(99, request("GET", "app.example", "/unused-canary"))  # Unknown source.
packet(12, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2(4, 0, 0, b""), port=8080)
# HPACK static indexed GET and http, followed by literal :authority and :path.
authority, path = b"app.example:8080", b"/unused-canary?private=2"
headers = bytes([0x82, 0x86, 1, len(authority)]) + authority
packet(12, h2(1, 1, 3, headers), port=8080)
packet(12, h2(9, 4, 3, bytes([4, len(path)]) + path), port=8080)
Path(__file__).with_name("hunts.pcap").write_bytes(capture)
