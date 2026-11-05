"""Create a small synthetic capture for PacketLens; contains no real user traffic."""
from pathlib import Path
import struct


def ip_packet(proto: int, source: bytes, dest: bytes, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64,
                         proto, 0, source, dest)
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    return ethernet + header + payload


def tcp(source_port: int, dest_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHIIHHHH", source_port, dest_port, 1, 0, 0x5018, 4096, 0, 0) + payload


dns = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x03org\x00\x00\x01\x00\x01"
udp = struct.pack("!HHHH", 54321, 53, 8 + len(dns), 0) + dns
packets = [
    ip_packet(17, b"\x0a\x00\x00\x02", b"\x08\x08\x08\x08", udp),
    ip_packet(6, b"\x0a\x00\x00\x02", b"\x5d\xb8\xd7\x0e",
              tcp(43210, 80, b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")),
    ip_packet(6, b"\x0a\x00\x00\x02", b"\x5d\xb8\xd7\x0e",
              tcp(43211, 443, b"\x16\x03\x03\x00\x00")),
]
capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
for index, packet in enumerate(packets):
    capture += struct.pack("<IIII", 1730000000 + index, 0, len(packet), len(packet)) + packet

target = Path(__file__).resolve().parents[1] / "app" / "src" / "main" / "assets" / "sample.pcap"
target.write_bytes(capture)
print(f"Created {target} ({len(capture)} bytes)")
