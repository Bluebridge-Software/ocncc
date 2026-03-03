# Copyright © 2026 Blue Bridge Software Ltd. All rights reserved.
#
# This material is the confidential property of Blue Bridge Software Ltd
# or its licensors and may be used, reproduced, stored or transmitted
# only in accordance with a valid Blue Bridge Software Ltd license or
# sublicense agreement.

from scapy.all import *
from scapy.layers.inet import TCP, IP
import struct
import binascii

# ================= CONFIG =================
USE_LITTLE_ENDIAN = True
ALIGN_SIZE = 4
NEW_DIRTY_MASK = 0x8001

# ================= TYPE CODES =================
NULL_TYPE   = 0x00
INT_TYPE    = 0x01
DATE_TYPE   = 0x02
SYMBOL_TYPE = 0x03
FLOAT_TYPE  = 0x04
STRING_TYPE = 0x05
ARRAY_TYPE  = 0x06
MAP_TYPE    = 0x07
RAW_TYPE    = 0x08

# ================= FOX SYMBOL TABLE =================
FOX_SYMBOLS = {
    0x48454E: "HEN",    # Example: Add all symbols from the FOX spec
    0x424F4E: "BON",    # Example: Add all symbols from the FOX spec
    0x564E554D: "VNUM", # Voucher Number
    0x41524546: "AREF", # Account Subscriber Reference
    0x57414C54: "WALT", # Wallet Identifier
    0x41435459: "ACTY", # Account Product Type
    0x4E554D20: "NUM",  # Number of Units/Events
    0x434C4920: "CLI",  # Calling Line Identifier
    0x444E2020: "DN",   # Dialled Number
    0x4552534C: "ERSL", # Preferred Reservation Length
    0x50524543: "PREC", # Precision
    0x44495343: "DISC", # Discount Override
    0x43445220: "CDR",  # CDR Array
    # Add more symbols as needed
}

# ================= FOX MESSAGE TYPE TABLE =================
FOX_MESSAGE_TYPES = {
    "IR  ": {"name": "Initial Reserve Seconds", "desc": "Initial Reserve Seconds Units"},
    "SR  ": {"name": "Subsequent Reserve Seconds", "desc": "Subsequent Reserve Seconds Units"},
    "CR  ": {"name": "Debit Seconds & Release", "desc": "Debit Seconds Units and Release"},
    # Add more message types as needed
}

# ================= HELPERS =================
def align(x):
    return (x + ALIGN_SIZE - 1) & ~(ALIGN_SIZE - 1)

def u16(buf, off):
    if USE_LITTLE_ENDIAN:
        return struct.unpack_from("<H", buf, off)[0]
    else:
        return struct.unpack_from(">H", buf, off)[0]

def u32(buf, off):
    if USE_LITTLE_ENDIAN:
        return struct.unpack_from("<I", buf, off)[0]
    else:
        return struct.unpack_from(">I", buf, off)[0]

def is_dirty(x):
    return (x & NEW_DIRTY_MASK) == NEW_DIRTY_MASK

def decode_symbol(val):
    c1 = (val >> 24) & 0xFF
    c2 = (val >> 16) & 0xFF
    c3 = (val >> 8) & 0xFF
    c4 = val & 0xFF
    return bytes([c1, c2, c3, c4]).decode("ascii", errors="replace")

def extract_key_parts(key):
    symbol = key & 0xffffe000
    typecode = (key >> 9) & 0x0f
    offset = (key & 0x1ff) << 2
    return symbol, typecode, offset

def get_fox_field_name(symbol):
    return FOX_SYMBOLS.get(symbol, f"UNKNOWN_{symbol:06X}")

# ================= DECODING FUNCTIONS =================
def decode_string(buf, off):
    strlen = buf[off]
    string_val = buf[off+1:off+1+strlen].decode("ascii", errors="replace")
    return string_val, off + 1 + strlen

def decode_date(buf, off):
    ts = u32(buf, off)
    return ts, off + 4

def decode_symbol_val(buf, off):
    sym = u32(buf, off)
    sym_str = decode_symbol(sym)
    return sym_str, off + 4

def decode_int(buf, off):
    val = u32(buf, off)
    return val, off + 4

def decode_float(buf, off):
    val = struct.unpack_from("<d", buf, off)[0] if USE_LITTLE_ENDIAN else struct.unpack_from(">d", buf, off)[0]
    return val, off + 8

def decode_raw(buf, off):
    raw_len = u32(buf, off)
    raw_val = buf[off+4:off+4+raw_len]
    return raw_val, off + 4 + raw_len

def decode_array(buf, off, indent):
    start = off
    byte_length = u16(buf, off)
    num_items = u16(buf, off + 2)
    print(f"{indent}Array ({num_items} items)")
    off += 4

    for i in range(num_items):
        index_val = u16(buf, off)
        typecode = (index_val >> 9) & 0x0f
        item_offset = (index_val & 0x1ff) << 2
        print(f"{indent}  Element [{i}] (Type: {typecode}, Offset: {item_offset})")
        off += 2

        if item_offset > 0:
            value_offset = start + item_offset
            decode_value(buf, value_offset, start, indent + "    ", typecode)

    return off

def decode_map(buf, off, indent):
    start = off
    byte_length = u16(buf, off)
    num_items = u16(buf, off + 2)
    print(f"{indent}Map ({num_items} entries)")
    off += 4

    for i in range(num_items):
        key_val = u32(buf, off)
        if is_dirty(key_val):
            print(f"{indent}  Dirty entry")
            return off + byte_length

        symbol, typecode, item_offset = extract_key_parts(key_val)
        fox_name = get_fox_field_name(symbol)
        print(f"{indent}  Entry [{i}]: {fox_name} (Type: {typecode}, Offset: {item_offset})")
        off += 4

        if item_offset > 0:
            value_offset = start + item_offset
            decode_value(buf, value_offset, start, indent + "    ", typecode, fox_name)

    return off

def decode_value(buf, value_offset, container_start, indent, typecode, fox_name=None):
    if typecode == NULL_TYPE:
        print(f"{indent}NULL")
        return

    if typecode == INT_TYPE:
        val, _ = decode_int(buf, value_offset)
        print(f"{indent}{fox_name or 'INT'}: {val}")

    elif typecode == FLOAT_TYPE:
        val, _ = decode_float(buf, value_offset)
        print(f"{indent}{fox_name or 'FLOAT'}: {val}")

    elif typecode == STRING_TYPE:
        val, _ = decode_string(buf, value_offset)
        print(f"{indent}{fox_name or 'STRING'}: {val}")

    elif typecode == DATE_TYPE:
        val, _ = decode_date(buf, value_offset)
        print(f"{indent}{fox_name or 'DATE'}: {val}")

    elif typecode == SYMBOL_TYPE:
        val, _ = decode_symbol_val(buf, value_offset)
        print(f"{indent}{fox_name or 'SYMBOL'}: {val}")

    elif typecode == ARRAY_TYPE:
        decode_array(buf, value_offset, indent)

    elif typecode == MAP_TYPE:
        decode_map(buf, value_offset, indent)

    elif typecode == RAW_TYPE:
        val, _ = decode_raw(buf, value_offset)
        print(f"{indent}{fox_name or 'RAW'}: {binascii.hexlify(val)}")

# ================= MAIN DECODER =================
def decode_fox_message(buf):
    offset = 0
    total_len = len(buf)

    while offset < total_len:
        if total_len - offset < 2:
            print("Incomplete message")
            return

        msg_len = u16(buf, offset)
        print(f"Message Length: {msg_len}")

        if msg_len == 0:
            print("Zero-length message")
            return

        if total_len - offset < msg_len:
            print("Message truncated")
            return

        print(f"\n=== FOX Message ===")
        start = offset
        byte_length = u16(buf, offset)
        num_items = u16(buf, offset + 2)
        print(f"Byte Length: {byte_length}, Number of Items: {num_items}")
        offset += 4

        fox_type = None
        fox_action = None

        for i in range(num_items):
            key_val = u32(buf, offset)
            symbol, _, item_offset = extract_key_parts(key_val)
            fox_name = get_fox_field_name(symbol)
            print(f"Item {i}: Symbol = {fox_name}")

            if fox_name == "TYPE" and item_offset > 0:
                value_offset = start + item_offset
                type_symbol = u32(buf, value_offset)
                fox_type = decode_symbol(type_symbol)
                print(f"FOX Type: {fox_type}")

            elif fox_name == "ACTN" and item_offset > 0:
                value_offset = start + item_offset
                action_symbol = u32(buf, value_offset)
                fox_action = decode_symbol(action_symbol)
                print(f"FOX Action: {fox_action}")

            offset += 4

        offset = start
        print("\n--- Header ---")
        decode_map(buf, offset, "  ")
        offset += byte_length

        if fox_type and fox_action:
            print(f"\n--- Body ({fox_type}, {fox_action}) ---")
            body_len = u16(buf, offset)
            decode_map(buf, offset, "  ")
            offset += body_len

# ================= PCAP PARSER =================
def parse_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    for pkt in packets:
        if TCP in pkt and pkt[TCP].dport == 12345:  # Replace 12345 with the FOX/ESCHER port
            payload = bytes(pkt[TCP].payload)
            if payload:
                print(f"\nPacket: {pkt.summary()}")
                decode_fox_message(payload)

# ================= MAIN =================
if __name__ == "__main__":
    pcap_file = "fox_capture.pcap"  # Replace with your PCAP file
    parse_pcap(pcap_file)

