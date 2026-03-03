#!/usr/bin/env python3

# Copyright © 2026 Blue Bridge Software Ltd. All rights reserved.
#
# This material is the confidential property of Blue Bridge Software Ltd
# or its licensors and may be used, reproduced, stored or transmitted
# only in accordance with a valid Blue Bridge Software Ltd license or
# sublicense agreement.

"""
Oracle ESCHER Protocol Codec - PRODUCTION VERSION  

Correctly handles 4-character symbols using auto-registration.
When encoding, all symbols from input JSON are automatically registered.
When decoding, registered symbols are expanded back to full 4-character form.

This matches how the C++ production code works: it knows full symbol names
(hardcoded like Symbol("ACTN")) and looks them up using truncated keys.
"""

import struct
import sys
import json
from datetime import datetime
from typing import Any, Dict, List, Tuple

# ====================  CONSTANTS ====================

ALIGN_SIZE = 4
EXT_HEADER_BLOCK_ID = 0xFFFE
NEW_DIRTY_MASK = 0x8001

NULL_TYPE = 0x00
INT_TYPE = 0x01
DATE_TYPE = 0x02
SYMBOL_TYPE = 0x03
FLOAT_TYPE = 0x04
STRING_TYPE = 0x05
ARRAY_TYPE = 0x06
MAP_TYPE = 0x07
RAW_TYPE = 0x08

# ==================== SYMBOL REGISTRY ====================

# Global registry: maps what's in wire format to full 4-char symbols
SYMBOL_REGISTRY = {}

def load_symbol_file(filename: str):
    """Load symbol mappings from JSON file"""
    try:
        with open(filename, 'r') as f:
            mappings = json.load(f)
            for wire_form, full_form in mappings.items():
                # Pad full form to 4 chars
                full_form = (full_form + "    ")[:4]
                SYMBOL_REGISTRY[wire_form.strip()] = full_form
            print(f"Loaded {len(mappings)} symbol mappings from {filename}")
    except FileNotFoundError:
        print(f"Symbol file {filename} not found - using auto-registration only")

def register_symbol(full_symbol: str):
    """Register a symbol for round-trip encoding/decoding"""
    if not full_symbol:
        return
    # Pad to 4 characters
    full_symbol = (full_symbol + "    ")[:4]
    # Calculate what it looks like in wire format (truncated)
    truncated = truncate_symbol(full_symbol)
    SYMBOL_REGISTRY[truncated] = full_symbol

def truncate_symbol(symbol_str: str) -> str:
    """Calculate how a symbol appears after encoding"""
    full_int = symbol_to_bytes(symbol_str)
    # Top 19 bits mask
    truncated_int = full_int & 0xFFFFE000
    return bytes_to_symbol(truncated_int)

def expand_symbol(wire_form: str) -> str:
    """Expand wire-format symbol to full 4-char using registry"""
    # Remove any trailing nulls/spaces for lookup
    wire_form_clean = wire_form.rstrip('\x00 ')
    if wire_form_clean in SYMBOL_REGISTRY:
        return SYMBOL_REGISTRY[wire_form_clean]
    # If not in registry, return wire form padded to 4 chars
    return (wire_form + "    ")[:4]

# ==================== HELPER FUNCTIONS ====================

def align(x: int) -> int:
    return (x + ALIGN_SIZE - 1) & ~(ALIGN_SIZE - 1)

def is_dirty(x: int) -> bool:
    return (x & NEW_DIRTY_MASK) == NEW_DIRTY_MASK

def symbol_to_bytes(symbol_str: str) -> int:
    symbol_str = (symbol_str + "    ")[:4]
    bytes_val = symbol_str.encode('ascii')
    return struct.unpack('>I', bytes_val)[0]

def bytes_to_symbol(symbol_int: int) -> str:
    bytes_val = struct.pack('>I', symbol_int)
    return bytes_val.decode('ascii', errors='replace').rstrip('\x00 ')

def extract_key_parts(key: int) -> Tuple[int, int, int]:
    symbol = key & 0xFFFFE000
    typecode = (key >> 9) & 0x0F
    offset = (key & 0x1FF) << 2
    return symbol, typecode, offset

def create_map_key(symbol: int, typecode: int, offset: int) -> int:
    symbol = symbol & 0xFFFFE000
    typecode = typecode & 0x0F
    word_offset = (offset >> 2) & 0x1FF
    return symbol | (typecode << 9) | word_offset

def extract_array_index(index: int) -> Tuple[int, int]:
    typecode = (index >> 9) & 0x0F
    offset = (index & 0x1FF) << 2
    return typecode, offset

def create_array_index(typecode: int, offset: int) -> int:
    typecode = typecode & 0x0F
    word_offset = (offset >> 2) & 0x1FF
    return (typecode << 9) | word_offset

# ==================== DECODER ====================

class EscherDecoder:
    def __init__(self, data: bytes):
        self.data = data
    
    def decode_message(self) -> Dict:
        return self.decode_map(0)
    
    def decode_value(self, typecode: int, offset: int) -> Any:
        if offset > len(self.data):
            raise ValueError(f"Offset beyond data")
        
        if typecode == NULL_TYPE:
            return None
        elif typecode == INT_TYPE:
            return self.decode_int(offset)
        elif typecode == DATE_TYPE:
            return self.decode_date(offset)
        elif typecode == SYMBOL_TYPE:
            return self.decode_symbol(offset)
        elif typecode == FLOAT_TYPE:
            return self.decode_float(offset)
        elif typecode == STRING_TYPE:
            return self.decode_string(offset)
        elif typecode == ARRAY_TYPE:
            return self.decode_array(offset)
        elif typecode == MAP_TYPE:
            return self.decode_map(offset)
        elif typecode == RAW_TYPE:
            return self.decode_raw(offset)
        else:
            raise ValueError(f"Unknown type: {typecode}")
    
    def decode_int(self, offset: int) -> int:
        if offset + 4 > len(self.data):
            raise ValueError("Not enough data for INT")
        return struct.unpack('>i', self.data[offset:offset+4])[0]
    
    def decode_date(self, offset: int) -> str:
        if offset + 4 > len(self.data):
            raise ValueError("Not enough data for DATE")
        timestamp = struct.unpack('>I', self.data[offset:offset+4])[0]
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def decode_symbol(self, offset: int) -> str:
        if offset + 4 > len(self.data):
            raise ValueError("Not enough data for SYMBOL")
        symbol_int = struct.unpack('>I', self.data[offset:offset+4])[0]
        return bytes_to_symbol(symbol_int)
    
    def decode_float(self, offset: int) -> float:
        if offset + 8 > len(self.data):
            raise ValueError("Not enough data for FLOAT")
        return struct.unpack('<d', self.data[offset:offset+8])[0]
    
    def decode_string(self, offset: int) -> str:
        if offset >= len(self.data):
            raise ValueError("Not enough data for STRING")
        
        strlen = self.data[offset]
        str_offset = 1
        
        if strlen & 0x80:
            if offset + 2 > len(self.data):
                raise ValueError("Not enough data for long STRING")
            strlen = struct.unpack('>H', self.data[offset:offset+2])[0] & 0x7FFF
            str_offset = 2
        
        end_offset = offset + str_offset + strlen
        if end_offset > len(self.data):
            raise ValueError("Not enough data for STRING content")
        
        return self.data[offset + str_offset:end_offset].decode('utf-8', errors='replace')
    
    def decode_raw(self, offset: int) -> bytes:
        if offset + 4 > len(self.data):
            raise ValueError("Not enough data for RAW")
        
        raw_len = struct.unpack('>I', self.data[offset:offset+4])[0]
        if offset + 4 + raw_len > len(self.data):
            raise ValueError("Not enough data for RAW content")
        
        return self.data[offset + 4:offset + 4 + raw_len]
    
    def decode_array(self, offset: int) -> List:
        if offset + 4 > len(self.data):
            raise ValueError("Not enough data for ARRAY")
        
        is_extended = False
        header_offset = 0
        
        if offset + 2 <= len(self.data):
            header_id = struct.unpack('>H', self.data[offset:offset+2])[0]
            if header_id == EXT_HEADER_BLOCK_ID:
                is_extended = True
                if offset + 3 <= len(self.data):
                    ctrl_len = self.data[offset + 2]
                    header_offset = (ctrl_len & 0x7F) - 1
                offset += 4 + header_offset
        
        if offset + 4 > len(self.data):
            raise ValueError("Not enough data for ARRAY header")
        
        if is_extended:
            if offset + 12 > len(self.data):
                raise ValueError("Not enough data for extended ARRAY")
            byte_length = struct.unpack('>I', self.data[offset:offset+4])[0]
            num_items = struct.unpack('>I', self.data[offset+8:offset+12])[0]
            offset += 12
        else:
            ptr_val = struct.unpack('>I', self.data[offset:offset+4])[0]
            if is_dirty(ptr_val):
                return ["<Dirty>"]
            
            byte_length = struct.unpack('>H', self.data[offset:offset+2])[0]
            num_items = struct.unpack('>H', self.data[offset+2:offset+4])[0]
            offset += 4
        
        items_start = offset
        result = []
        
        for i in range(num_items):
            if offset + 2 > len(self.data):
                break
            
            index_val = struct.unpack('>H', self.data[offset:offset+2])[0]
            typecode, item_offset = extract_array_index(index_val)
            offset += 2
            
            if item_offset > 0:
                value_offset = items_start + item_offset
                if value_offset < len(self.data):
                    try:
                        value = self.decode_value(typecode, value_offset)
                        result.append(value)
                    except Exception as e:
                        result.append(f"<Error: {e}>")
                else:
                    result.append(None)
            else:
                result.append(None)
        
        return result
    
    def decode_map(self, offset: int) -> Dict:
        if offset + 4 > len(self.data):
            raise ValueError("Not enough data for MAP")
        
        is_extended = False
        header_offset = 0
        
        if offset + 2 <= len(self.data):
            header_id = struct.unpack('>H', self.data[offset:offset+2])[0]
            if header_id == EXT_HEADER_BLOCK_ID:
                is_extended = True
                if offset + 3 <= len(self.data):
                    ctrl_len = self.data[offset + 2]
                    header_offset = (ctrl_len & 0x7F) - 1
                offset += 4 + header_offset
        
        if offset + 4 > len(self.data):
            raise ValueError("Not enough data for MAP header")
        
        if is_extended:
            if offset + 12 > len(self.data):
                raise ValueError("Not enough data for extended MAP")
            byte_length = struct.unpack('>I', self.data[offset:offset+4])[0]
            num_items = struct.unpack('>I', self.data[offset+8:offset+12])[0]
            offset += 12
        else:
            ptr_val = struct.unpack('>I', self.data[offset:offset+4])[0]
            if is_dirty(ptr_val):
                return {"<Dirty>": True}
            
            byte_length = struct.unpack('>H', self.data[offset:offset+2])[0]
            num_items = struct.unpack('>H', self.data[offset+2:offset+4])[0]
            offset += 4
        
        items_start = offset
        result = {}
        
        for i in range(num_items):
            if offset + 4 > len(self.data):
                break
            
            key_val = struct.unpack('>I', self.data[offset:offset+4])[0]
            symbol, typecode, item_offset = extract_key_parts(key_val)
            symbol_str = bytes_to_symbol(symbol)
            
            # Expand symbol using registry
            symbol_str = expand_symbol(symbol_str)
            
            offset += 4
            
            if item_offset > 0:
                value_offset = items_start + item_offset
                if value_offset < len(self.data):
                    try:
                        value = self.decode_value(typecode, value_offset)
                        result[symbol_str] = value
                    except Exception as e:
                        result[symbol_str] = f"<Error: {e}>"
                else:
                    result[symbol_str] = None
            else:
                result[symbol_str] = None
        
        return result

# ==================== ENCODER ====================

class EscherEncoder:
    def encode_message(self, obj: Dict) -> bytes:
        if not isinstance(obj, dict):
            raise ValueError("Top-level must be dict")
        
        # Auto-register all symbols from input
        self._register_all_symbols(obj)
        
        return self.encode_map(obj)
    
    def _register_all_symbols(self, obj: Any):
        """Recursively register all symbols from input"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str):
                    register_symbol(key)
                self._register_all_symbols(value)
        elif isinstance(obj, list):
            for item in obj:
                self._register_all_symbols(item)
    
    def encode_value(self, value: Any) -> Tuple[int, bytes]:
        if value is None:
            return NULL_TYPE, b''
        elif isinstance(value, bool):
            return INT_TYPE, struct.pack('>i', 1 if value else 0)
        elif isinstance(value, int):
            return INT_TYPE, struct.pack('>i', value)
        elif isinstance(value, float):
            return FLOAT_TYPE, struct.pack('<d', value)
        elif isinstance(value, str):
            if len(value) <= 4 and all(c.isupper() or c == ' ' for c in value):
                return SYMBOL_TYPE, struct.pack('>I', symbol_to_bytes(value))
            else:
                str_bytes = value.encode('utf-8')
                strlen = len(str_bytes)
                
                if strlen < 128:
                    result = struct.pack('B', strlen) + str_bytes
                else:
                    result = struct.pack('>H', strlen | 0x8000) + str_bytes
                
                padding = align(len(result)) - len(result)
                result += b'\x00' * padding
                return STRING_TYPE, result
        elif isinstance(value, list):
            return ARRAY_TYPE, self.encode_array(value)
        elif isinstance(value, dict):
            return MAP_TYPE, self.encode_map(value)
        elif isinstance(value, bytes):
            raw_len = len(value)
            result = struct.pack('>I', raw_len) + value
            padding = align(len(result)) - len(result)
            result += b'\x00' * padding
            return RAW_TYPE, result
        else:
            raise ValueError(f"Unsupported type: {type(value)}")
    
    def encode_array(self, items: List) -> bytes:
        num_items = len(items)
        
        encoded_values = []
        for item in items:
            typecode, data = self.encode_value(item)
            encoded_values.append((typecode, data))
        
        index_section_size = num_items * 2
        data_section = bytearray()
        indices = []
        
        for typecode, data in encoded_values:
            if len(data) > 0:
                offset = index_section_size + len(data_section)
                indices.append(create_array_index(typecode, offset))
                data_section.extend(data)
            else:
                indices.append(create_array_index(typecode, 0))
        
        total_size = 4 + index_section_size + len(data_section)
        
        result = bytearray()
        result.extend(struct.pack('>HH', total_size, num_items))
        
        for index in indices:
            result.extend(struct.pack('>H', index))
        
        result.extend(data_section)
        
        return bytes(result)
    
    def encode_map(self, items: Dict) -> bytes:
        num_items = len(items)
        
        encoded_values = []
        for key, value in items.items():
            key_padded = (key + "    ")[:4]
            symbol_int = symbol_to_bytes(key_padded)
            typecode, data = self.encode_value(value)
            encoded_values.append((symbol_int, typecode, data))
        
        index_section_size = num_items * 4
        data_section = bytearray()
        keys = []
        
        for symbol_int, typecode, data in encoded_values:
            if len(data) > 0:
                offset = index_section_size + len(data_section)
                keys.append(create_map_key(symbol_int, typecode, offset))
                data_section.extend(data)
            else:
                keys.append(create_map_key(symbol_int, typecode, 0))
        
        total_size = 4 + index_section_size + len(data_section)
        
        result = bytearray()
        result.extend(struct.pack('>HH', total_size, num_items))
        
        for key in keys:
            result.extend(struct.pack('>I', key))
        
        result.extend(data_section)
        
        return bytes(result)

# ==================== FILE I/O ====================

def decode_file(input_file: str, output_file: str = None, symbol_file: str = None):
    # Load symbol mappings if provided
    if symbol_file:
        load_symbol_file(symbol_file)
    
    with open(input_file, 'rb') as f:
        data = f.read()
    
    decoder = EscherDecoder(data)
    result = decoder.decode_message()
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
            f.write('\n')  # Add trailing newline for consistency
        print(f"Decoded to {output_file}")
    else:
        print(json.dumps(result, indent=2))
    
    return result

def encode_file(input_file: str, output_file: str):
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    encoder = EscherEncoder()
    result = encoder.encode_message(data)
    
    with open(output_file, 'wb') as f:
        f.write(result)
    
    print(f"Encoded to {output_file} ({len(result)} bytes)")
    return result

# ==================== MAIN ====================

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  Decode: python3 escher_codec.py decode <input.escher> [output.json] [symbols.json]")
        print("  Encode: python3 escher_codec.py encode <input.json> <output.escher>")
        print()
        print("Symbols are auto-registered during encoding.")
        print("For decoding, provide a symbols.json file to map wire-format symbols to full names.")
        sys.exit(1)
    
    command = sys.argv[1]
    input_file = sys.argv[2]
    
    if command == 'decode':
        output_file = sys.argv[3] if len(sys.argv) > 3 else None
        symbol_file = sys.argv[4] if len(sys.argv) > 4 else None
        decode_file(input_file, output_file, symbol_file)
    elif command == 'encode':
        if len(sys.argv) < 4:
            print("Error: Output file required")
            sys.exit(1)
        output_file = sys.argv[3]
        encode_file(input_file, output_file)
    else:
        print(f"Error: Unknown command '{command}'")
        sys.exit(1)

if __name__ == '__main__':
    main()
