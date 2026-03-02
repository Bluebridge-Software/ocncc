#!/usr/bin/env python3
"""
Extract all ESCHER_SYMBOL definitions from C++ code and create symbols.json

This creates a complete symbol registry for your application.
"""

import sys
import re
import struct
import json

def symbol_to_wire_format(symbol_4char):
    """Calculate the truncated wire format of a symbol"""
    # Pad to 4 chars
    symbol = (symbol_4char + "    ")[:4]
    # Convert to 32-bit int
    symbol_int = struct.unpack('>I', symbol.encode('ascii'))[0]
    # Apply 19-bit mask
    wire_int = symbol_int & 0xFFFFE000
    # Convert back
    wire_bytes = struct.pack('>I', wire_int)
    return wire_bytes.decode('ascii').rstrip('\x00 ')

def extract_symbols_from_file(filename):
    """Extract all ESCHER_SYMBOL definitions from a C++ file"""
    symbols = {}
    
    try:
        with open(filename, 'r', errors='ignore') as f:
            content = f.read()
            
        # Pattern: ESCHER_SYMBOL(KEY_NAME, "SYMB");
        pattern = r'ESCHER_SYMBOL\s*\([^,]+,\s*"([^"]+)"\s*\)'
        
        matches = re.findall(pattern, content)
        
        for full_symbol in matches:
            # Pad to 4 characters
            full_padded = (full_symbol + "    ")[:4]
            # Calculate wire format
            wire = symbol_to_wire_format(full_padded)
            # Store mapping
            symbols[wire] = full_padded
            
    except Exception as e:
        print(f"Error reading {filename}: {e}", file=sys.stderr)
    
    return symbols

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_symbols.py <header_files...> > symbols.json")
        print()
        print("Example:")
        print("  python3 extract_symbols.py *.hh *.cc > symbols.json")
        sys.exit(1)
    
    all_symbols = {}
    
    for filename in sys.argv[1:]:
        symbols = extract_symbols_from_file(filename)
        all_symbols.update(symbols)
        print(f"Extracted {len(symbols)} symbols from {filename}", file=sys.stderr)
    
    print(f"\nTotal unique symbols: {len(all_symbols)}", file=sys.stderr)
    print(f"Writing to symbols.json...", file=sys.stderr)
    
    # Sort by wire format for readability
    sorted_symbols = dict(sorted(all_symbols.items()))
    
    # Output JSON
    print(json.dumps(sorted_symbols, indent=2))

if __name__ == '__main__':
    main()
