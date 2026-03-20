#!/usr/bin/env python3
"""
escher_to_pcap.py

Copyright © 2026 Blue Bridge Software Ltd. All rights reserved.

This material is the confidential property of Blue Bridge Software Ltd
or its licensors and may be used, reproduced, stored or transmitted
only in accordance with a valid Blue Bridge Software Ltd license or
sublicense agreement.

-----------------
Convert a JSON array of ESCHER messages into a PCAP file that Wireshark
decodes correctly with escher_dissector.lua (TCP port 1500).

Usage:
    python3 escher_to_pcap.py input.json output.pcap

JSON format:
  An array of message objects. Each key is a 4-char ESCHER symbol (padded with
  spaces to 4 chars if needed). Values can be:
    - int        -> INT32 (or INT64 if out of 32-bit range)
    - float      -> FLOAT64
    - str        -> SYMBOL if exactly 4 chars from A-Z+SPACE, else STRING
    - dict       -> nested MAP
    - list       -> ARRAY
    - null/None  -> NULL (presence flag)
    - "~date:N"  -> DATE typecode with unix timestamp N

Notes:
  - Symbols shorter than 4 chars are right-padded with spaces: "WI" -> "WI  "
  - The DATE type is explicitly selected by using the string "~date:TIMESTAMP"
  - FLOAT64 values are byte-reversed on the wire (Linux htonf convention)
"""

import struct, json, sys, time, math
from pathlib import Path

# ---------------------------------------------------------------------------
# Symbol encoding
# ---------------------------------------------------------------------------
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

def pad_sym(s):
    """Pad a symbol key to exactly 4 chars."""
    return (s + "    ")[:4]

def is_symbol_value(s):
    """True if string looks like a bare 4-char ESCHER symbol value."""
    if len(s) != 4:
        return False
    return all(c in ALPHABET for c in s)

def encode_symbol_int(s):
    assert len(s) == 4
    return (ALPHABET.index(s[0]) * 161243136 +
            ALPHABET.index(s[1]) *   5971968 +
            ALPHABET.index(s[2]) *    221184 +
            ALPHABET.index(s[3]) *      8192)

# ---------------------------------------------------------------------------
# Type codes
# ---------------------------------------------------------------------------
TC_NULL   = 0
TC_INT32  = 1
TC_DATE   = 2
TC_SYMBOL = 3
TC_FLOAT  = 4
TC_STRING = 5
TC_ARRAY  = 6
TC_RAW    = 8
TC_INT64  = 9
TC_MAP    = 12

# ---------------------------------------------------------------------------
# Value encoders
# ---------------------------------------------------------------------------
def align4(n):
    return (n + 3) & ~3

def encode_string(s):
    b = s.encode('utf-8')
    n = len(b)
    hdr = bytes([n]) if n < 128 else struct.pack('>H', n | 0x8000)
    raw = hdr + b
    return raw + b'\x00' * (align4(len(raw)) - len(raw))

def encode_float64_wire(v):
    """Byte-reverse the double (Linux htonf convention)."""
    return bytes(reversed(struct.pack('>d', v)))

def encode_value(v):
    """Return (typecode, encoded_bytes) for a Python value."""
    if v is None:
        return TC_NULL, b''
    if isinstance(v, str) and v.startswith('~date:'):
        ts = int(v[6:])
        return TC_DATE, struct.pack('>I', ts)
    if isinstance(v, bool):
        # JSON booleans: treat true as NULL (presence flag), false omit
        return TC_NULL, b''
    if isinstance(v, int):
        if -2147483648 <= v <= 2147483647:
            return TC_INT32, struct.pack('>i', v)
        else:
            return TC_INT64, struct.pack('>q', v)
    if isinstance(v, float):
        return TC_FLOAT, encode_float64_wire(v)
    if isinstance(v, str):
        if is_symbol_value(v):
            return TC_SYMBOL, struct.pack('>I', encode_symbol_int(v))
        return TC_STRING, encode_string(v)
    if isinstance(v, dict):
        return TC_MAP, encode_map(v)
    if isinstance(v, list):
        return TC_ARRAY, encode_array(v)
    raise ValueError(f"Cannot encode {type(v).__name__}: {v!r}")

# ---------------------------------------------------------------------------
# Map / Array encoders
# ---------------------------------------------------------------------------
def encode_map(d):
    entries = []
    for raw_key, val in d.items():
        if raw_key.startswith("_"):  # skip comment keys
            continue
        key = pad_sym(raw_key)
        tc, data = encode_value(val)
        entries.append((key, tc, data))

    n = len(entries)
    # Standard map: 8-byte header + n*4 index + data
    data_start = align4(8 + n * 4)

    offsets = []
    data_parts = []
    pos = data_start
    for key, tc, data in entries:
        if tc == TC_NULL or len(data) == 0:
            offsets.append(0)
        else:
            offsets.append(pos // 4)
            data_parts.append(data)
            pos += len(data)

    total_len = pos
    buf = bytearray(total_len)

    struct.pack_into('>H', buf, 0, total_len)
    struct.pack_into('>H', buf, 2, n)
    struct.pack_into('>I', buf, 4, 0)   # internal_ptr = 0

    for i, (key, tc, data) in enumerate(entries):
        sym_val = encode_symbol_int(key)
        entry = (sym_val & 0xFFFFE000) | ((tc & 0xF) << 9) | (offsets[i] & 0x1FF)
        struct.pack_into('>I', buf, 8 + i * 4, entry)

    pos = data_start
    for data in data_parts:
        buf[pos:pos + len(data)] = data
        pos += len(data)

    return bytes(buf)


def encode_array(lst):
    entries = []
    for val in lst:
        tc, data = encode_value(val)
        entries.append((tc, data))

    n = len(entries)
    data_start = align4(8 + n * 2)

    offsets = []
    data_parts = []
    pos = data_start
    for tc, data in entries:
        if tc == TC_NULL or len(data) == 0:
            offsets.append(0)
        else:
            offsets.append(pos // 4)
            data_parts.append(data)
            pos += len(data)

    total_len = pos
    buf = bytearray(total_len)

    struct.pack_into('>H', buf, 0, total_len)
    struct.pack_into('>H', buf, 2, n)
    struct.pack_into('>I', buf, 4, 0)

    for i, (tc, data) in enumerate(entries):
        entry = ((tc & 0xF) << 9) | (offsets[i] & 0x1FF)
        struct.pack_into('>H', buf, 8 + i * 2, entry)

    pos = data_start
    for data in data_parts:
        buf[pos:pos + len(data)] = data
        pos += len(data)

    return bytes(buf)

# ---------------------------------------------------------------------------
# PCAP writer
# ---------------------------------------------------------------------------
PCAP_GLOBAL_HEADER = struct.pack('<IHHiIII',
    0xa1b2c3d4,   # magic
    2, 4,         # version
    0,            # timezone
    0,            # sig figs
    65535,        # snaplen
    1             # network: Ethernet
)

def ethernet_ip_tcp_wrap(payload, src_port=12345, dst_port=1500, seq=1):
    """Wrap a payload in Ethernet + IP + TCP headers."""
    # TCP
    tcp_header = struct.pack('>HHIIBBHHH',
        src_port,   # src port
        dst_port,   # dst port
        seq,        # seq
        0,          # ack
        0x50,       # data offset (5 * 4 = 20 bytes) + reserved
        0x18,       # flags: PSH + ACK
        65535,      # window
        0,          # checksum (0 = unchecked)
        0           # urgent
    )

    # IP
    total_ip_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack('>BBHHHBBH4s4s',
        0x45,           # version=4, IHL=5
        0,              # DSCP
        total_ip_len,
        0,              # id
        0x4000,         # flags: don't fragment
        64,             # TTL
        6,              # protocol: TCP
        0,              # checksum (0 = unchecked)
        b'\xc0\xa8\x01\x01',   # src IP: 192.168.1.1
        b'\xc0\xa8\x01\x02'    # dst IP: 192.168.1.2
    )

    # Ethernet
    eth_header = (
        b'\x00\x11\x22\x33\x44\x55'   # dst MAC
        b'\x66\x77\x88\x99\xaa\xbb'   # src MAC
        b'\x08\x00'                    # EtherType: IPv4
    )

    frame = eth_header + ip_header + tcp_header + payload
    return frame

def make_pcap_record(frame, ts_sec, ts_usec=0):
    incl_len = len(frame)
    orig_len = len(frame)
    header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
    return header + frame

def write_pcap(messages, output_path):
    ts_base = int(time.time())
    records = []

    for i, msg in enumerate(messages):
        payload = encode_map(msg)
        frame = ethernet_ip_tcp_wrap(payload, src_port=20000 + i, dst_port=1500, seq=i + 1)
        record = make_pcap_record(frame, ts_base + i, i * 100000)
        records.append(record)

    with open(output_path, 'wb') as f:
        f.write(PCAP_GLOBAL_HEADER)
        for r in records:
            f.write(r)

    print(f"Written {len(records)} packets to {output_path}")

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 3:
        print("Usage: escher_to_pcap.py input.json output.pcap")
        sys.exit(1)

    json_path = sys.argv[1]
    pcap_path = sys.argv[2]

    with open(json_path) as f:
        data = json.load(f)

    if isinstance(data, dict):
        messages = [data]
    elif isinstance(data, list):
        messages = data
    else:
        print("ERROR: JSON must be an object or array of objects")
        sys.exit(1)

    write_pcap(messages, pcap_path)

if __name__ == '__main__':
    main()