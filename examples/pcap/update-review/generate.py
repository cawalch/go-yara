"""Write synthetic Ethernet PCAPs for the update rule and entity regressions."""

from pathlib import Path
from struct import pack
from ipaddress import IPv4Address

CLIENT, PROXY, RESOLVER = map(IPv4Address, ("192.0.2.10", "192.0.2.20", "192.0.2.53"))
HOST = "updates.example"
OUT = Path(__file__).parent


def checksum(data):
    data += b"\0" * (len(data) % 2)
    value = sum(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return ~value & 65535


def ip(src, dst, protocol, data):
    header = pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(data), 0, 0, 64, protocol, 0,
                  src.packed, dst.packed)
    return b"\0" * 12 + b"\x08\x00" + header[:10] + pack("!H", checksum(header)) + header[12:] + data


def udp(src, dst, sport, dport, data):
    return ip(src, dst, 17, pack("!4H", sport, dport, 8 + len(data), 0) + data)


def tcp(src, dst, sport, dport, seq, ack, flags, data=b""):
    header = pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 4096, 0, 0)
    pseudo = src.packed + dst.packed + pack("!BBH", 0, 6, len(header) + len(data))
    return ip(src, dst, 6, header[:16] + pack("!H", checksum(pseudo + header + data)) + header[18:] + data)


def dns():
    question = b"".join(bytes([len(label)]) + label.encode() for label in HOST.split(".")) + b"\0"
    question += pack("!HH", 1, 1)
    query = pack("!6H", 7, 0x0100, 1, 0, 0, 0) + question
    answer = pack("!6H", 7, 0x8180, 1, 1, 0, 0) + question
    answer += b"\xc0\x0c" + pack("!HHIH", 1, 1, 30, 4) + PROXY.packed
    return [udp(CLIENT, RESOLVER, 42000, 53, query), udp(RESOLVER, CLIENT, 53, 42000, answer)]


def exchange(port, target, body, byte_range=None, *, split_request=False):
    request = f"GET {target} HTTP/1.1\r\nHost: {HOST}\r\n"
    status = "200 OK\r\n"
    if byte_range is not None:
        start, end, size = byte_range
        request += f"Range: bytes={start}-{end}\r\n"
        status = f"206 Partial Content\r\nContent-Range: bytes {start}-{end}/{size}\r\n"
    request = (request + "\r\n").encode()
    response = f"HTTP/1.1 {status}Content-Length: {len(body)}\r\n\r\n".encode() + body
    frames = [
        tcp(CLIENT, PROXY, port, 80, 100, 0, 0x02),
        tcp(PROXY, CLIENT, 80, port, 500, 101, 0x12),
    ]
    if split_request:
        frames.append(tcp(CLIENT, PROXY, port, 80, 101, 501, 0x18, request[:8]))
        frames.append(tcp(CLIENT, PROXY, port, 80, 109, 501, 0x18, request[8:]))
    else:
        frames.append(tcp(CLIENT, PROXY, port, 80, 101, 501, 0x18, request))
    frames.append(tcp(PROXY, CLIENT, 80, port, 501, 101 + len(request), 0x18, response))
    return frames


def write(name, frames):
    with (OUT / name).open("wb") as out:
        out.write(pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            out.write(pack("<IIII", 1700000000, i * 1000, len(frame), len(frame)))
            out.write(frame)


marker = b"artifact_id=REVOKED-BUILD-042\n"
good = b"artifact_id=APPROVED-BUILD-042\n"
write("positive.pcap", dns() + exchange(41000, "/updates/client", marker))
write("control.pcap", dns() + exchange(41000, "/updates/client", good)
      + exchange(41001, "/diagnostics", marker))
write("positive-split.pcap", dns() + exchange(41000, "/updates/client", marker, split_request=True))
(OUT / "unavailable.pcap").write_bytes((OUT / "positive.pcap").read_bytes()[:-10])
write("entities.pcap",
      exchange(41000, "/updates/client", marker)
      + exchange(41001, "/diagnostics", b"diagnostics-only\n")
      + exchange(41002, "/updates/range", marker, (3, len(marker) + 2, len(marker) + 3))
      + exchange(41003, "/updates/unseen", b"")[:-1])
