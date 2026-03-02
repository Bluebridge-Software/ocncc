# Oracle OCNCC Escher Protocol Wireshark Dissector

## Overview

This Wireshark dissector plugin decodes binary Escher messages used in Oracle Communications Network Charging and Control (OCNCC) platform. Escher (Eserv Structured Communications Hierarchical Encoding Rules) is a portable, flexible, and efficient message encoding scheme.

## Protocol Description

### Message Structure

Escher messages are hierarchical structures that can contain:

- **Maps**: Key-value pairs where keys are 4-byte symbols
- **Arrays**: Ordered sequences of values
- **Primitive Types**: 
  - NULL (0x00)
  - Integer (0x01) - 32-bit signed
  - Date (0x02) - time_t (32-bit timestamp)
  - Symbol (0x03) - 4-byte identifier
  - Float (0x04) - 64-bit double
  - String (0x05) - Variable length with 1 or 2 byte length prefix
  - Raw (0x08) - Binary data with 32-bit length prefix

### Encoding Format

#### Standard Map/Array Header (4 bytes)
```
Offset  Size  Description
0       2     Byte length of entire structure
2       2     Number of items
```

#### Extended Map/Array Header (with 0xFFFE marker)
```
Offset  Size  Description
0       2     Extended Header ID (0xFFFE)
2       1     Control block length
3       1     Control block data
4       4     Byte length (32-bit)
8       4     Number of items (32-bit)
```

#### Map Key Encoding (32-bit)
```
Bits    Description
31-13   Symbol (19 bits)
12-9    Type code (4 bits)
8-0     Offset in 32-bit words (9 bits)
```

#### Array Index Encoding (16-bit)
```
Bits    Description
15-9    Type code (4 bits, shifted)
8-0     Offset in 32-bit words (9 bits)
```

### Dirty Flag

Maps and Arrays can be "dirty" (modified in memory). The dirty flag uses bits 15 and 0 of the first 32-bit word:
- If `(value & 0x8001) == 0x8001`, the structure contains a pointer to unpacked data
- Otherwise, it contains the byte length and item count

## Installation

### Method 1: User Plugin Directory (Recommended)

1. Copy `escher_dissector.lua` to your Wireshark personal plugins directory:

   **Windows:**
   ```
   %APPDATA%\Wireshark\plugins\
   ```

   **Linux:**
   ```
   ~/.local/lib/wireshark/plugins/
   ```

   **macOS:**
   ```
   ~/.config/wireshark/plugins/
   ```

2. Restart Wireshark

### Method 2: Global Plugin Directory

1. Copy `escher_dissector.lua` to the global plugins directory:

   **Windows:**
   ```
   C:\Program Files\Wireshark\plugins\<version>\
   ```

   **Linux:**
   ```
   /usr/lib/wireshark/plugins/<version>/
   or
   /usr/local/lib/wireshark/plugins/<version>/
   ```

   **macOS:**
   ```
   /Applications/Wireshark.app/Contents/PlugIns/wireshark/<version>/
   ```

2. Restart Wireshark

### Method 3: Load Manually

1. Open Wireshark
2. Go to **Tools** → **Lua** → **Evaluate**
3. Browse to `escher_dissector.lua` and click **Open**

Note: This method requires reloading the script each time Wireshark starts.

## Configuration

### Port Assignment

By default, the dissector registers for TCP/UDP ports 5000 and 5001. To change these:

1. Edit `escher_dissector.lua`
2. Modify the port registration section:
```lua
tcp_port:add(YOUR_PORT, escher_proto)
udp_port:add(YOUR_PORT, escher_proto)
```

### Using "Decode As..."

If your Escher traffic uses different ports:

1. Capture some traffic
2. Right-click on a packet
3. Select **Decode As...**
4. Set **Current** to **ESCHER**
5. Click **OK**

## Usage

### Viewing Decoded Messages

Once installed, Escher messages will be automatically decoded when detected on registered ports.

The packet details pane will show:
- Protocol: **ESCHER**
- Hierarchical tree structure showing:
  - Map/Array containers
  - Key names (for maps)
  - Type codes
  - Values

### Display Filters

Use these display filters to find specific Escher messages:

```
# All Escher messages
escher

# Messages with specific value types
escher.type == 0x01          # Integer values
escher.type == 0x05          # String values
escher.type == 0x07          # Maps

# Messages with extended headers
escher.extended == 1

# Messages with specific symbols (must know encoded value)
escher.map.symbol contains "WGR"

# Dirty (modified) structures
escher.dirty == 1

# Integer value filters
escher.int > 1000
escher.int == 0

# String content filters
escher.string contains "recharge"
```

### Color Rules

You can create color rules for Escher messages:

1. Go to **View** → **Coloring Rules**
2. Click **New**
3. Set filter: `escher`
4. Choose colors
5. Click **OK**

## Example: General Wallet Recharge Message

The `ccsGeneralWalletRecharge.cc` example shows a handler for WGR (Wallet General Recharge) messages.

A typical message structure would be:
```
Map (Top Level Message)
├─ 'HEAD' → Map (Message Header)
│  ├─ 'VERS' → Int (Protocol Version)
│  ├─ 'TIME' → Date (Timestamp)
│  └─ 'TYPE' → Symbol ('WGR ')
├─ 'BODY' → Map (Message Body)
│  ├─ 'ACCT' → String (Account ID)
│  ├─ 'AMNT' → Int (Recharge Amount)
│  └─ 'CURR' → Symbol (Currency)
└─ 'TAIL' → Map (Message Trailer)
   └─ 'CKSU' → Int (Checksum)
```

## Troubleshooting

### Plugin Not Loading

1. Check Wireshark version compatibility (tested with Wireshark 3.x and 4.x)
2. Verify Lua is enabled: **Help** → **About Wireshark** → **Plugins**
3. Check for errors: **Tools** → **Lua** → **Evaluate** → load the script manually

### Messages Not Decoded

1. Verify the traffic is on a registered port
2. Use "Decode As..." to force decoding
3. Check if the message starts with valid Escher header:
   - Standard: 16-bit length + 16-bit item count
   - Extended: 0xFFFE marker

### Incorrect Decoding

1. Verify byte order (network order/big-endian expected)
2. Check alignment - values are padded to 4-byte boundaries
3. Examine the hex dump to verify structure matches protocol

### Performance Issues

For large captures with many Escher messages:
1. Apply capture filters to reduce traffic
2. Use display filters to show only relevant packets
3. Consider disabling the dissector temporarily if not needed

## Advanced Usage

### Extracting Escher Messages

To extract and save Escher messages:

1. Apply filter: `escher`
2. **File** → **Export Specified Packets**
3. Save as PCAP or PCAPNG

### Converting to Text

To convert captured Escher messages to text format:

1. Use the provided `cmnEscherDecode` utility (if available):
   ```bash
   cmnEscherDecode < message.bin > message.txt
   ```

2. Or use tshark:
   ```bash
   tshark -r capture.pcap -Y escher -T fields -e escher
   ```

## Technical Notes

### Implementation Details

- **Byte Order**: Network byte order (big-endian)
- **Alignment**: 4-byte alignment for all values
- **String Encoding**: 
  - Length < 128: 1 byte length
  - Length ≥ 128: 2 byte length with bit 15 set (length & 0x7FFF)
- **Extended Format**: Used when structures exceed 2048 bytes
- **Dirty Detection**: Prevents decoding of unpacked (in-memory) structures

### Limitations

1. Does not decode pointer values in dirty structures (these are memory addresses)
2. Maximum tested message size: 64KB (standard), 4GB (extended)
3. Assumes messages are complete in single packets (no fragmentation handling)
4. Symbol decoding uses simple ASCII conversion (may show escape codes for non-printable chars)

## Protocol References

Based on OCNCC (Oracle Communications Network Charging and Control) implementation files:
- `cmnEscher.hh` - Main protocol definitions
- `cmnEscherPickle.hh/.cc` - Binary encoding/decoding
- `cmnEscherMapImpl.hh/.cc` - Map container implementation
- `cmnEscherArrayImpl.hh/.cc` - Array container implementation
- `cmnEscherEntry.hh/.cc` - Value encoding
- `cmnEscherContainerImpl.hh` - Common container utilities

## Support

For issues or questions:
1. Verify your Escher implementation matches this format
2. Check that messages are encoded in network byte order
3. Ensure proper 4-byte alignment throughout
4. Review the source code comments for encoding details

## License

This dissector is provided as-is for analysis of Oracle OCNCC Escher protocol traffic.
Ensure you have appropriate authorization to analyze network traffic in your environment.

## Version History

- v1.0 (2024) - Initial release
  - Support for standard and extended Maps/Arrays
  - All basic type decoding
  - Dirty flag detection
  - Hierarchical display

## Contributing

To enhance the dissector:
1. Add heuristic detection for better port-independent decoding
2. Implement reassembly for fragmented messages  
3. Add protocol-specific message type detection
4. Create export functionality for decoded messages
5. Add statistics and flow analysis
