"""Generate the synthetic DNS fixture using Python 3 and documentation IPs."""
from pathlib import Path
from struct import pack

capture = bytearray(pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
client, resolver = bytes([192, 0, 2, 10]), bytes([192, 0, 2, 53])


def packet(txid, name, code=None, extended=0):
    reply = code is not None
    qname = b"".join(bytes([len(s)]) + s.encode() for s in name.split(".")) + b"\0"
    msg = pack("!6H", txid, (0x8180 | code) if reply else 0x0100, 1, 0, 0, bool(extended))
    msg += qname + pack("!HH", 1, 1)
    if extended:
        msg += b"\0" + pack("!HHIH", 41, 1232, extended << 24, 0)
    udp = pack("!4H", 53 if reply else 53000, 53000 if reply else 53, len(msg) + 8, 0)
    ip = pack("!BBHHHBBH", 0x45, 0, 28 + len(msg), 0, 0, 64, 17, 0)
    ip += resolver + client if reply else client + resolver
    total = sum(int.from_bytes(ip[i:i+2], "big") for i in range(0, 20, 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    data = ip[:10] + pack("!H", total ^ 65535) + ip[12:] + udp + msg
    capture.extend(pack("<4I", 1700000000, len(capture), len(data), len(data)) + data)


for txid, name, code in [(1, "api.example", 3), (2, "api.example", 2),
                         (3, "api.example", 0), (4, "other.example", 3)]:
    packet(txid, name)
    packet(txid, name.upper(), code)
packet(5, "api.example")
packet(6, "api.example", 2)
packet(7, "api.example")
packet(7, "api.example")
packet(7, "api.example", 3)
packet(8, "api.example")
packet(8, "api.example", 2, extended=1)
Path(__file__).with_name("service.pcap").write_bytes(capture)
