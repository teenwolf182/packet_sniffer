import os
import sys
import logging
import signal
from collections import Counter

# Suppress scapy warning messages before loading
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
except ImportError:
    print("[-] Error: Scapy library not found. Run: sudo pip3 install scapy")
    sys.exit(1)

# Protocol mapping table
PROTOCOL_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Global counters for summary metrics
stats = Counter(Total=0, TCP=0, UDP=0, ICMP=0, Other=0)

def signal_handler(sig, frame):
    """Gracefully prints packet metrics summary upon Ctrl+C exit."""
    print("\n\n" + "=" * 50)
    print("                SNIFFER SUMMARY STATISTICS       ")
    print("=" * 50)
    print(f" Total Packets Captured : {stats['Total']}")
    print(f" TCP Packets            : {stats['TCP']}")
    print(f" UDP Packets            : {stats['UDP']}")
    print(f" ICMP Packets           : {stats['ICMP']}")
    print(f" Unclassified/Other     : {stats['Other']}")
    print("=" * 50)
    print("[+] Packet sniffing session successfully closed.")
    sys.exit(0)

# Register the termination signal handler
signal.signal(signal.SIGINT, signal_handler)

def process_packet(packet):
    """Callback function executed automatically for every packet captured."""
    # Ensure packet has an IP layer to read addresses
    if not packet.haslayer(IP):
        stats["Other"] += 1
        stats["Total"] += 1
        return

    stats["Total"] += 1
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto_num = ip_layer.proto
    proto_name = PROTOCOL_MAP.get(proto_num, f"Proto-{proto_num}")

    # Build basic packet tracking string
    log_msg = f"[{proto_name}] {src_ip} -> {dst_ip}"

    # Extract layer-specific details (Ports & Flags)
    if packet.haslayer(TCP):
        stats["TCP"] += 1
        tcp = packet[TCP]
        log_msg += f" | Src Port: {tcp.sport} -> Dst Port: {tcp.dport} | Flags: {tcp.underlayer.sprintf('%TCP.flags%')}"
    
    elif packet.haslayer(UDP):
        stats["UDP"] += 1
        udp = packet[UDP]
        log_msg += f" | Src Port: {udp.sport} -> Dst Port: {udp.dport}"
        
    elif packet.haslayer(ICMP):
        stats["ICMP"] += 1
        icmp = packet[ICMP]
        log_msg += f" | Type: {icmp.type} Code: {icmp.code}"
    else:
        stats["Other"] += 1

    print(log_msg)

    # Decode and print raw payloads (Banner/Data leakage checking)
    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore').strip()
            if payload:
                # Indent lines neatly underneath the main packet log
                indented_payload = "\n    | ".join(payload.splitlines()[:3]) # Limit to first 3 lines
                print(f"    | Raw Payload Data:\n    | {indented_payload}")
        except Exception:
            pass

def main():
    # Verify root execution requirements
    if os.getuid() != 0:
        print("[-] Access Denied: Packet sniffing requires administrative root privileges.")
        print("    Please run with: sudo python3 packet_sniffer.py")
        sys.exit(1)

    print("=" * 60)
    print("                 REAL-TIME NETWORK PACKET SNIFFER       ")
    print("=" * 60)
    print("Available Network Interfaces:")
    print("  " + ", ".join(get_if_list()))
    print("-" * 60)
    
    interface = input("Enter interface to sniff (Leave empty for default): ").strip()
    if not interface:
        interface = None  # Scapy defaults to the primary active connection route
        
    print(f"\n[+] Active listening initiated on interface: {interface or 'System Default'}")
    print("[+] Press Ctrl+C at any time to pause transmission and view log metrics.\n")
    print(f"{'PROTOCOL & ROUTING':<35} | {'PORT / LAYER METADATA'}")
    print("-" * 75)

    # Start the continuous packet sniffing engine
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    main()
