# Copyright © 2026 Blue Bridge Software Ltd. All rights reserved.
#
# This material is the confidential property of Blue Bridge Software Ltd
# or its licensors and may be used, reproduced, stored or transmitted
# only in accordance with a valid Blue Bridge Software Ltd license or
# sublicense agreement.
# 

import struct
import time
import socket

# ============================================================
# Utility: Internet Checksum
# ============================================================

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

# ============================================================
# PCAP Headers
# ============================================================

def pcap_global_header():
    return struct.pack(
        '<IHHIIII',
        0xa1b2c3d4,  # magic
        2, 4,       # version
        0, 0,
        65535,
        1           # LINKTYPE_ETHERNET
    )

def pcap_packet_header(packet_len):
    ts = int(time.time())
    return struct.pack('<IIII', ts, 0, packet_len, packet_len)

# ============================================================
# Ethernet Header
# ============================================================

def ethernet_header():
    dst_mac = b'\x00\x11\x22\x33\x44\x55'
    src_mac = b'\x66\x77\x88\x99\xaa\xbb'
    eth_type = struct.pack("!H", 0x0800)  # IPv4
    return dst_mac + src_mac + eth_type

# ============================================================
# IPv4 Header
# ============================================================

def ipv4_header(payload_len):
    version_ihl = 0x45
    tos = 0
    total_length = 20 + payload_len
    identification = 0
    flags_fragment = 0
    ttl = 64
    proto = 6  # TCP
    checksum_placeholder = 0

    src_ip = socket.inet_aton("192.168.0.1")
    dst_ip = socket.inet_aton("192.168.0.2")

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        proto,
        checksum_placeholder,
        src_ip,
        dst_ip
    )

    chksum = checksum(header)

    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        proto,
        chksum,
        src_ip,
        dst_ip
    )

# ============================================================
# TCP Header
# ============================================================

def tcp_header(payload, src_port=50000, dst_port=1700):
    seq = 1
    ack = 0
    data_offset = 5
    flags = 0x18  # PSH + ACK
    window = 1024
    checksum_placeholder = 0
    urg_ptr = 0

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset << 4,
        flags,
        window,
        checksum_placeholder,
        urg_ptr
    )

    # Pseudo header for checksum
    src_ip = socket.inet_aton("192.168.0.1")
    dst_ip = socket.inet_aton("192.168.0.2")
    placeholder = 0
    protocol = 6
    tcp_length = len(tcp_header) + len(payload)

    pseudo_header = struct.pack(
        "!4s4sBBH",
        src_ip,
        dst_ip,
        placeholder,
        protocol,
        tcp_length
    )

    tcp_checksum = checksum(pseudo_header + tcp_header + payload)

    return struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset << 4,
        flags,
        window,
        tcp_checksum,
        urg_ptr
    )

# ============================================================
# FOX Payload (Valid Map > 28 bytes)
# ============================================================

def build_fox_payload():
    # Values (must be 4-byte aligned)
    actn_val = b"TEST"
    type_val = b"REQ "
    ping_val = b"PING"

    values = actn_val + type_val + ping_val

    num_items = 3

    # Header is 4 bytes
    header_len = 4
    entries_len = num_items * 4

    # Items start immediately after header + entries
    items_start = header_len + entries_len

    entries = b''

    def make_key(symbol, typecode, value_offset_bytes):
        sym_val = struct.unpack(">I", symbol)[0]

        # Offset must be relative to items_start
        encoded_offset = (value_offset_bytes // 4) & 0x1FF

        key = (sym_val & 0xFFFFE000) | (typecode << 9) | encoded_offset
        return struct.pack(">I", key)

    # Offsets relative to items_start
    offset = 0
    entries += make_key(b"ACTN", 0x03, offset)
    offset += 4

    entries += make_key(b"TYPE", 0x03, offset)
    offset += 4

    entries += make_key(b"PING", 0x03, offset)

    total_length = header_len + entries_len + len(values)

    header = struct.pack(">HH", total_length, num_items)

    return header + entries + values

def build_fox_payload1():
    # Create values
    actn_val = b"TEST"
    type_val = b"REQ "
    pad_val  = b"PING"  # extra entry to increase size

    # Offsets must be multiples of 4
    offset = 0
    entries = b''

    def make_key(symbol, typecode, value_offset):
        sym_val = struct.unpack(">I", symbol)[0]
        key = (sym_val & 0xFFFFE000) | (typecode << 9) | ((value_offset // 4) & 0x1FF)
        return struct.pack(">I", key)

    # ACTN
    entries += make_key(b"ACTN", 0x03, offset)
    offset += 4

    # TYPE
    entries += make_key(b"TYPE", 0x03, offset)
    offset += 4

    # PING
    entries += make_key(b"PING", 0x03, offset)
    offset += 4

    values = actn_val + type_val + pad_val

    num_items = 3
    total_length = 4 + len(entries) + len(values)

    header = struct.pack(">HH", total_length, num_items)

    return header + entries + values

# ============================================================
# Build Packet
# ============================================================

def build_packet():
    fox_payload = build_fox_payload()
    tcp = tcp_header(fox_payload)
    ip = ipv4_header(len(tcp) + len(fox_payload))
    eth = ethernet_header()
    return eth + ip + tcp + fox_payload

# ============================================================
# Write PCAP
# ============================================================

def write_pcap(filename="fox_valid.pcap"):
    with open(filename, "wb") as f:
        f.write(pcap_global_header())

        packet = build_packet()
        f.write(pcap_packet_header(len(packet)))
        f.write(packet)

    print(f"Created {filename}")

if __name__ == "__main__":
    write_pcap()
