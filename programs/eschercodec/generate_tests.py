#!/usr/bin/env python3
"""
Complete Test Suite for ESCHER/FOX Dissectors

Generates test messages, encodes them, creates PCAPs, and provides testing instructions.
"""

import sys
import os
import json
import subprocess

# ==================== TEST MESSAGES ====================

TEST_MESSAGES = {
    "escher_simple": {
        "description": "Simple ESCHER message with basic types",
        "port": 1500,
        "data": {
            "NAME": "Test",
            "ID": 12345,
            "VAL": 3.14159
        }
    },
    
    "escher_nested": {
        "description": "Nested ESCHER message with maps and arrays",
        "port": 1500,
        "data": {
            "USER": "Alice",
            "DATA": [
                {"KEY": "value1", "NUM": 100},
                {"KEY": "value2", "NUM": 200}
            ],
            "PI": 3.14159
        }
    },
    
    "fox_initial_reservation": {
        "description": "FOX Initial Reservation Request",
        "port": 1700,
        "data": {
            "ACTN": "REQ ",
            "TYPE": "IR  ",
            "HEAD": {
                "CMID": 12345,
                "SVID": 1,
                "VER ": 1
            },
            "BODY": {
                "CLI ": "447700900123",
                "AREF": "ACC001",
                "WALT": "WALLET123"
            }
        }
    },
    
    "fox_wallet_info": {
        "description": "FOX Wallet Information Request",
        "port": 1700,
        "data": {
            "ACTN": "REQ ",
            "TYPE": "WI  ",
            "HEAD": {
                "CMID": 67890,
                "SVID": 2,
                "VER ": 1
            },
            "BODY": {
                "WALT": "WALLET456"
            }
        }
    },
    
    "fox_ack": {
        "description": "FOX Acknowledgement",
        "port": 1700,
        "data": {
            "ACTN": "ACK ",
            "TYPE": "IR  ",
            "HEAD": {
                "CMID": 12345,
                "SVID": 1,
                "VER ": 1
            },
            "BODY": {
                "CODE": "OK  "
            }
        }
    }
}

# ==================== TEST GENERATION ====================

def generate_test_files(output_dir="test_output"):
    """Generate all test files"""
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print("=" * 60)
    print("ESCHER/FOX Dissector Test Suite")
    print("=" * 60)
    print()
    
    codec_script = "escher_codec.py"
    pcap_script = "create_test_pcap.py"
    
    # Check if scripts exist
    if not os.path.exists(codec_script):
        print(f"ERROR: {codec_script} not found!")
        print(f"Please run this script from the directory containing {codec_script}")
        return False
    
    if not os.path.exists(pcap_script):
        print(f"ERROR: {pcap_script} not found!")
        return False
    
    all_files = []
    
    for test_name, test_data in TEST_MESSAGES.items():
        print(f"Generating test: {test_name}")
        print(f"  Description: {test_data['description']}")
        
        # Create JSON input file
        json_file = os.path.join(output_dir, f"{test_name}.json")
        with open(json_file, 'w') as f:
            json.dump(test_data['data'], f, indent=2)
        print(f"  ✓ Created {json_file}")
        
        # Encode to ESCHER
        escher_file = os.path.join(output_dir, f"{test_name}.escher")
        cmd = ['python3', codec_script, 'encode', json_file, escher_file]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  ✗ Encoding failed: {result.stderr}")
            continue
        print(f"  ✓ Encoded to {escher_file}")
        
        # Create PCAP
        pcap_file = os.path.join(output_dir, f"{test_name}.pcap")
        port_arg = ['--port', str(test_data['port'])]
        cmd = ['python3', pcap_script, escher_file, pcap_file] + port_arg
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  ✗ PCAP creation failed: {result.stderr}")
            continue
        print(f"  ✓ Created {pcap_file}")
        
        all_files.append({
            'name': test_name,
            'description': test_data['description'],
            'json': json_file,
            'escher': escher_file,
            'pcap': pcap_file,
            'port': test_data['port']
        })
        
        print()
    
    # Create test summary
    summary_file = os.path.join(output_dir, "TEST_SUMMARY.md")
    with open(summary_file, 'w') as f:
        f.write("# ESCHER/FOX Dissector Test Files\n\n")
        f.write("## Generated Test Cases\n\n")
        
        for file_info in all_files:
            f.write(f"### {file_info['name']}\n\n")
            f.write(f"**Description:** {file_info['description']}\n\n")
            f.write(f"**Files:**\n")
            f.write(f"- JSON input: `{os.path.basename(file_info['json'])}`\n")
            f.write(f"- ESCHER binary: `{os.path.basename(file_info['escher'])}`\n")
            f.write(f"- PCAP: `{os.path.basename(file_info['pcap'])}`\n")
            f.write(f"- Port: {file_info['port']} ({'FOX' if file_info['port'] == 1700 else 'ESCHER'})\n\n")
            f.write("**Wireshark Filter:**\n")
            f.write(f"```\ntcp.port == {file_info['port']}\n```\n\n")
            f.write("---\n\n")
        
        f.write("## Testing Instructions\n\n")
        f.write("1. **Install Dissectors:**\n")
        f.write("   ```bash\n")
        f.write("   # Copy dissectors to Wireshark plugins directory\n")
        f.write("   cp escher_dissector_friendly.lua ~/.local/lib/wireshark/plugins/\n")
        f.write("   cp fox_dissector_friendly.lua ~/.local/lib/wireshark/plugins/\n")
        f.write("   ```\n\n")
        f.write("2. **Open PCAP in Wireshark:**\n")
        f.write("   - File → Open\n")
        f.write("   - Select a .pcap file from above\n\n")
        f.write("3. **Apply Filter:**\n")
        f.write("   - For ESCHER: `tcp.port == 1500`\n")
        f.write("   - For FOX: `tcp.port == 1700`\n\n")
        f.write("4. **Verify Dissection:**\n")
        f.write("   - Click on a packet with data\n")
        f.write("   - Expand the ESCHER or FOX protocol section\n")
        f.write("   - Verify symbols show full names like \"ACTN [AC@]\"\n\n")
        f.write("5. **Test Decoding:**\n")
        f.write("   ```bash\n")
        f.write("   # Decode any ESCHER file back to JSON\n")
        f.write("   python3 escher_codec.py decode <file>.escher output.json\n")
        f.write("   ```\n\n")
        f.write("## Expected Results\n\n")
        f.write("- ✅ Symbols displayed as full names: \"ACTN\", \"TYPE\", \"BODY\", \"HEAD\"\n")
        f.write("- ✅ Wire format shown in brackets: \"ACTN [AC@]\"\n")
        f.write("- ✅ Values decoded correctly (strings, integers, floats)\n")
        f.write("- ✅ Nested structures (maps, arrays) properly displayed\n")
        f.write("- ✅ Info column shows message type for FOX messages\n\n")
    
    print("=" * 60)
    print(f"✓ Generated {len(all_files)} test cases")
    print(f"✓ Test summary: {summary_file}")
    print("=" * 60)
    print()
    print("Next steps:")
    print(f"  1. cd {output_dir}")
    print(f"  2. cat TEST_SUMMARY.md")
    print(f"  3. Open any .pcap file in Wireshark")
    
    return True

# ==================== MAIN ====================

def main():
    output_dir = "test_output"
    
    if len(sys.argv) > 1:
        output_dir = sys.argv[1]
    
    success = generate_test_files(output_dir)
    
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main()
