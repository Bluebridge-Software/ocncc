# Dissector Testing Quick Reference

## Complete Workflow

### 1. Generate Test PCAPs

**Automatic (recommended):**
```bash
# Generate all test cases
python3 generate_tests.py

# This creates test_output/ with:
# - 5 test messages (JSON, ESCHER, PCAP)
# - TEST_SUMMARY.md with details
```

**Manual:**
```bash
# From JSON to PCAP
python3 escher_codec.py encode message.json message.escher
python3 create_test_pcap.py message.escher message.pcap

# For FOX protocol
python3 create_test_pcap.py message.escher message.pcap --fox
```

### 2. Install Dissectors

```bash
# Linux
mkdir -p ~/.local/lib/wireshark/plugins/
cp escher_dissector_friendly.lua ~/.local/lib/wireshark/plugins/
cp fox_dissector_friendly.lua ~/.local/lib/wireshark/plugins/

# macOS
mkdir -p ~/Library/Application\ Support/Wireshark/plugins/
cp escher_dissector_friendly.lua ~/Library/Application\ Support/Wireshark/plugins/
cp fox_dissector_friendly.lua ~/Library/Application\ Support/Wireshark/plugins/

# Windows
# Copy to: %APPDATA%\Wireshark\plugins\
```

### 3. Test in Wireshark

1. **Restart Wireshark** (required after installing dissectors)

2. **Verify dissectors loaded:**
   - Help → About Wireshark → Plugins
   - Look for: escher_dissector_friendly.lua, fox_dissector_friendly.lua

3. **Open a test PCAP:**
   - File → Open → `test_output/fox_initial_reservation.pcap`

4. **Apply filter:**
   ```
   tcp.port == 1700
   ```
   (or `tcp.port == 1500` for ESCHER)

5. **Check dissection:**
   - Click packet #4 (the one with data)
   - Expand "FOX Protocol" or "ESCHER Protocol"
   - Verify symbols show as: `ACTN [AC@]`, `TYPE [TY@]`, etc.

## Test Cases Generated

| File | Protocol | Port | Description |
|------|----------|------|-------------|
| `escher_simple.pcap` | ESCHER | 1500 | Basic types (string, int, float) |
| `escher_nested.pcap` | ESCHER | 1500 | Nested maps and arrays |
| `fox_initial_reservation.pcap` | FOX | 1700 | IR Request message |
| `fox_wallet_info.pcap` | FOX | 1700 | WI Request message |
| `fox_ack.pcap` | FOX | 1700 | Acknowledgement message |

## Verification Checklist

- [ ] Dissectors appear in Wireshark → About → Plugins
- [ ] PCAP opens without errors
- [ ] Filter `tcp.port == 1700` shows packets
- [ ] Packet #4 has FOX/ESCHER protocol section
- [ ] Symbols show full names: "ACTN" not "AC@"
- [ ] Wire format shown in brackets: "ACTN [AC@]"
- [ ] Values decoded correctly:
  - [ ] Strings: "REQ ", "IR  "
  - [ ] Integers: 12345
  - [ ] Floats: 3.14159
- [ ] Nested structures expand correctly
- [ ] Info column shows message type (FOX only)

## Common Issues

### Dissector not appearing
- **Solution:** Check file is in correct plugins directory
- **Verify:** `ls ~/.local/lib/wireshark/plugins/` shows .lua files
- **Fix:** Restart Wireshark completely

### Protocol not decoded
- **Solution:** Check port number matches
  - ESCHER uses port 1500
  - FOX uses port 1700
- **Verify:** Filter `tcp.port == 1500` or `tcp.port == 1700`

### Symbols still truncated ("AC@" instead of "ACTN")
- **Solution:** You're using the old dissector
- **Fix:** Replace with `*_friendly.lua` versions
- **Verify:** Check SYMBOL_MAP is in the dissector file

### Scapy not installed (for create_test_pcap.py)
```bash
pip install scapy
```
Or the script will use manual PCAP creation (works without scapy)

## Creating Your Own Test

```bash
# 1. Create JSON message
cat > my_message.json << 'EOF'
{
  "ACTN": "REQ ",
  "TYPE": "WI  ",
  "HEAD": {
    "CMID": 99999,
    "SVID": 3
  },
  "BODY": {
    "WALT": "TEST123"
  }
}
EOF

# 2. Encode to Escher
python3 escher_codec.py encode my_message.json my_message.escher

# 3. Create PCAP
python3 create_test_pcap.py my_message.escher my_message.pcap --fox

# 4. Open in Wireshark
wireshark my_message.pcap &
```

## Decoding Messages

```bash
# Decode any Escher binary back to JSON
python3 escher_codec.py decode message.escher output.json

# With symbol mapping (optional)
python3 escher_codec.py decode message.escher output.json complete_symbols.json

# Compare original and decoded
diff -u original.json decoded.json
```

## Files You Need

| File | Purpose |
|------|---------|
| `escher_codec.py` | Encode/decode Escher messages |
| `create_test_pcap.py` | Create PCAPs from Escher files |
| `generate_tests.py` | Generate complete test suite |
| `escher_dissector_friendly.lua` | ESCHER dissector with symbols |
| `fox_dissector_friendly.lua` | FOX dissector with symbols |
| `complete_symbols.json` | Full symbol mapping (optional) |

## Quick Commands

```bash
# Generate all tests
python3 generate_tests.py

# Install dissectors (Linux)
cp *_friendly.lua ~/.local/lib/wireshark/plugins/

# Open test in Wireshark
wireshark test_output/fox_initial_reservation.pcap

# Verify encoding/decoding
python3 escher_codec.py encode test.json test.escher
python3 escher_codec.py decode test.escher verify.json
diff test.json verify.json  # Should be identical
```

## Success Criteria

✅ **Working correctly when:**
- Wireshark shows "FOX Protocol" or "ESCHER Protocol" in packet details
- Symbols display as "ACTN [AC@]" (full name with wire format)
- All values decode correctly
- Nested structures expand properly
- Can filter on protocol fields

🎉 **You're done!** The dissectors are working correctly.
