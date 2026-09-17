# Real-Time Network Packet Sniffer

A powerful, light-weight network inspection tool written in **Python** using the **Scapy** library. 

This script captures live network packets passing through your system's interface, decodes network layer metrics (IP, TCP, UDP, ICMP), dumps legible raw payloads, and aggregates real-time traffic statistics upon termination.

---

## 🚀 Features
* **Multi-Protocol Decoding:** Gracefully extracts source/destination routing, transport layer ports, and TCP flags for **TCP**, **UDP**, and **ICMP** protocols.
* **Payload Inspection:** Captures raw application text payloads and safely prints printable string blocks (useful for identifying cleartext traffic or header leakage).
* **Live Traffic Summary:** Utilizes low-overhead native signal interceptors (`Ctrl+C`) to cleanly break operation and generate a compiled traffic summary matrix.
* **Interface Selection:** Lists all available host network interfaces at boot and lets you pick an adapter dynamically or stick to the system default route.

---

## 🛠️ Requirements & Installation

This script runs on Python 3 and demands lower-layer hook privileges to turn on promiscuous mode for raw network interfaces.

### 1. Clone the project repository
```bash
git clone https://github.com](https://github.com/teenwolf182/packet_sniffer.git
cd packet_sniffer
```

### 2. Install dependencies
Because the engine communicates closely with network frames, dependencies must be installed globally or matching your administrative profile:
```bash
sudo pip3 install scapy
```

---

## 💻 Usage

Run the sniffer with system administrator rights (`sudo`). This is mandatory so `Scapy` can set your interface adapter card into **promiscuous mode** to capture network layers.

```bash
sudo python3 packet_sniffer.py
```

### Interactive Usage Workflow:
```text
============================================================
                 REAL-TIME NETWORK PACKET SNIFFER       
============================================================
Available Network Interfaces:
  lo, eth0, wlan0, docker0
------------------------------------------------------------
Enter interface to sniff (Leave empty for default): eth0

[+] Active listening initiated on interface: eth0
[+] Press Ctrl+C at any time to pause transmission and view log metrics.

PROTOCOL & ROUTING                  | PORT / LAYER METADATA
---------------------------------------------------------------------------
[TCP] 192.168.1.15 -> 93.184.216.34 | Src Port: 54102 -> Dst Port: 80 | Flags: S
[TCP] 93.184.216.34 -> 192.168.1.15 | Src Port: 80 -> Dst Port: 54102 | Flags: SA
[TCP] 192.168.1.15 -> 93.184.216.34 | Src Port: 54102 -> Dst Port: 80 | Flags: A
    | Raw Payload Data:
    | GET / HTTP/1.1
    | Host: example.com
    | User-Agent: curl/7.81.0

^C

==================================================
                SNIFFER SUMMARY STATISTICS       
==================================================
 Total Packets Captured : 3
 TCP Packets            : 3
 UDP Packets            : 0
 ICMP Packets           : 0
 Unclassified/Other     : 0
==================================================
[+] Packet sniffing session successfully closed.
```

---

## ⚠️ Disclaimer
This utility is intended exclusively for **educational purposes**, system troubleshooting, and **authorized network auditing**. Analyzing structural packets over networks you do not own or possess explicit management validation for is strictly illegal. Use responsibly.
