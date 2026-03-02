#!/usr/bin/env python3
"""
ESCHER/FOX PCAP Generator for Wireshark Testing

Creates PCAP files from Escher binary messages for testing Lua dissectors.
Supports both ESCHER (port 1500) and FOX (port 1700) protocols.

Usage:
    python3 create_test_pcap.py message.escher output.pcap [--port PORT]
    python3 create_test_pcap.py --fox message.escher output.pcap
"""

import sys
import struct
import time

try:
    from scapy.all import IP, TCP, Ether, wrpcap, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ==================== MANUAL PCAP CREATION ====================

class PcapWriter:
    """Manual PCAP file writer (if scapy not available)"""
    
    PCAP_GLOBAL_HEADER = struct.pack(
        'IHHiIII',
        0xa1b2c3d4,  # magic number
        2, 4,        # version 2.4
        0, 0,        # GMT offset, timestamp accuracy
        65535,       # max packet length
        1            # Ethernet
    )
    
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.file.write(self.PCAP_GLOBAL_HEADER)
    
    def write_packet(self, ethernet_frame, timestamp=None):
        if timestamp is None:
            timestamp = time.time()
        
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        packet_len = len(ethernet_frame)
        
        packet_header = struct.pack('IIII', ts_sec, ts_usec, packet_len, packet_len)
        self.file.write(packet_header)
        self.file.write(ethernet_frame)
    
    def close(self):
        self.file.close()

def calculate_checksum(data):
    """Calculate Internet checksum"""
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_ethernet_frame(src_mac, dst_mac, payload):
    """Create Ethernet frame"""
    src = bytes.fromhex(src_mac.replace(':', ''))
    dst = bytes.fromhex(dst_mac.replace(':', ''))
    eth_type = struct.pack('>H', 0x0800)
    return dst + src + eth_type + payload

def create_ip_packet(src_ip, dst_ip, payload, protocol=6):
    """Create IPv4 packet"""
    version_ihl = 0x45
    total_length = 20 + len(payload)
    src_ip_bytes = bytes(map(int, src_ip.split('.')))
    dst_ip_bytes = bytes(map(int, dst_ip.split('.')))
    
    header = struct.pack('!BBHHHBBH', 0x45, 0, total_length, 0x1234, 0x4000, 64, protocol, 0) + src_ip_bytes + dst_ip_bytes
    checksum = calculate_checksum(header)
    header = struct.pack('!BBHHHBBH', 0x45, 0, total_length, 0x1234, 0x4000, 64, protocol, checksum) + src_ip_bytes + dst_ip_bytes
    
    return header + payload

def create_tcp_packet(src_ip, dst_ip, src_port, dst_port, payload, seq, ack, flags):
    """Create TCP packet"""
    data_offset = 5 << 4
    
    tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, data_offset, flags, 65535, 0, 0)
    
    src_ip_bytes = bytes(map(int, src_ip.split('.')))
    dst_ip_bytes = bytes(map(int, dst_ip.split('.')))
    pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack('!BBH', 0, 6, len(tcp_header) + len(payload))
    
    checksum = calculate_checksum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, data_offset, flags, 65535, checksum, 0)
    
    return tcp_header + payload

# ==================== SCAPY METHOD ====================

def create_pcap_scapy(escher_data, output_file, src_ip, dst_ip, src_port, dst_port):
    """Create PCAP using scapy"""
    packets = []
    seq_c, seq_s = 1000, 2000
    
    # SYN
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='S', seq=seq_c))
    seq_c += 1
    
    # SYN-ACK
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='SA', seq=seq_s, ack=seq_c))
    seq_s += 1
    
    # ACK
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A', seq=seq_c, ack=seq_s))
    
    # DATA
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq_c, ack=seq_s)/Raw(load=escher_data))
    seq_c += len(escher_data)
    
    # ACK from server
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='A', seq=seq_s, ack=seq_c))
    
    # FIN
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='FA', seq=seq_c, ack=seq_s))
    seq_c += 1
    
    # FIN-ACK
    packets.append(Ether()/IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags='FA', seq=seq_s, ack=seq_c))
    seq_s += 1
    
    # Final ACK
    packets.append(Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags='A', seq=seq_c, ack=seq_s))
    
    wrpcap(output_file, packets)
    print(f"✓ Created PCAP with {len(packets)} packets using scapy")

# ==================== MANUAL METHOD ====================

def create_pcap_manual(escher_data, output_file, src_ip, dst_ip, src_port, dst_port):
    """Create PCAP manually"""
    writer = PcapWriter(output_file)
    src_mac, dst_mac = '00:11:22:33:44:55', '00:aa:bb:cc:dd:ee'
    seq_c, seq_s = 1000, 2000
    ts = time.time()
    
    # SYN
    tcp = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, b'', seq_c, 0, 0x02)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    writer.write_packet(create_ethernet_frame(src_mac, dst_mac, ip), ts)
    seq_c += 1
    ts += 0.001
    
    # SYN-ACK
    tcp = create_tcp_packet(dst_ip, src_ip, dst_port, src_port, b'', seq_s, seq_c, 0x12)
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    writer.write_packet(create_ethernet_frame(dst_mac, src_mac, ip), ts)
    seq_s += 1
    ts += 0.001
    
    # ACK
    tcp = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, b'', seq_c, seq_s, 0x10)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    writer.write_packet(create_ethernet_frame(src_mac, dst_mac, ip), ts)
    ts += 0.001
    
    # DATA
    tcp = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, escher_data, seq_c, seq_s, 0x18)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    writer.write_packet(create_ethernet_frame(src_mac, dst_mac, ip), ts)
    seq_c += len(escher_data)
    ts += 0.001
    
    # ACK from server
    tcp = create_tcp_packet(dst_ip, src_ip, dst_port, src_port, b'', seq_s, seq_c, 0x10)
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    writer.write_packet(create_ethernet_frame(dst_mac, src_mac, ip), ts)
    ts += 0.001
    
    # FIN
    tcp = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, b'', seq_c, seq_s, 0x11)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    writer.write_packet(create_ethernet_frame(src_mac, dst_mac, ip), ts)
    seq_c += 1
    ts += 0.001
    
    # FIN-ACK
    tcp = create_tcp_packet(dst_ip, src_ip, dst_port, src_port, b'', seq_s, seq_c, 0x11)
    ip = create_ip_packet(dst_ip, src_ip, tcp)
    writer.write_packet(create_ethernet_frame(dst_mac, src_mac, ip), ts)
    seq_s += 1
    ts += 0.001
    
    # Final ACK
    tcp = create_tcp_packet(src_ip, dst_ip, src_port, dst_port, b'', seq_c, seq_s, 0x10)
    ip = create_ip_packet(src_ip, dst_ip, tcp)
    writer.write_packet(create_ethernet_frame(src_mac, dst_mac, ip), ts)
    
    writer.close()
    print(f"✓ Created PCAP with 8 packets using manual method")

# ==================== MAIN ====================

def create_pcap(escher_file, output_file, port=1500, src_ip='192.168.1.100', dst_ip='192.168.1.200'):
    with open(escher_file, 'rb') as f:
        escher_data = f.read()
    
    print(f"Read {len(escher_data)} bytes from {escher_file}")
    
    src_port = 50000
    
    if SCAPY_AVAILABLE:
        create_pcap_scapy(escher_data, output_file, src_ip, dst_ip, src_port, port)
    else:
        create_pcap_manual(escher_data, output_file, src_ip, dst_ip, src_port, port)
    
    print(f"✓ Created {output_file}")
    print(f"  Protocol: {'FOX' if port == 1700 else 'ESCHER'}")
    print(f"  Port: {port}")
    print(f"  Message size: {len(escher_data)} bytes")
    print()
    print("Next steps:")
    print(f"  1. Open {output_file} in Wireshark")
    print(f"  2. Apply filter: tcp.port == {port}")
    print(f"  3. Look for {'FOX' if port == 1700 else 'ESCHER'} protocol in packet details")

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 create_test_pcap.py <escher_file> <output.pcap> [--port PORT]")
        print("  python3 create_test_pcap.py <escher_file> <output.pcap> --fox")
        print()
        print("Examples:")
        print("  python3 create_test_pcap.py message.escher test.pcap")
        print("  python3 create_test_pcap.py fox_message.escher test.pcap --fox")
        sys.exit(1)
    
    escher_file = sys.argv[1]
    output_file = sys.argv[2]
    port = 1500
    
    if '--fox' in sys.argv:
        port = 1700
    elif '--port' in sys.argv:
        idx = sys.argv.index('--port')
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])
    
    create_pcap(escher_file, output_file, port=port)

if __name__ == '__main__':
    main()
