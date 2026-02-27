# Private IP Address Infernece Behind NAT 

This project performs private IP address inference and TCP hijacking attack behind a NAT.
There are two steps to the attack:
1. Inferring client-side ephemeral ports in use in the NAT
2. Inferring NATed clients communicating with a target server

### Prerequisites
#### System Requirements
- Linux (tested Ubuntu 24.02)
- Root access (For packet injection)

#### Dependencies
##### Scapy (Required)
```bash
sudo apt update
sudo apt install scapy
```
### 1. Inferring Client Ports in Use
#### Configuration
Edit `port_infer.py` and fill in the configuration section:

###### ---------- CONFIG ----------
 ```python
IFACE = "wlo1"                 # Network interface
START_PORT = 32768             # Ephemeral port range start
END_PORT = 65535               # Ephemeral port range end
attacker_ip = "192.168.0.10"   # Attacker's private IP inside NAT
server_ip = " "          # Target server IP e.g., 4.4.4.4
SERVER_PORT = 22               # Target server port
nat_ip = " "             # NAT public IP e.g., 6.6.8.8
```

Run the script in live mode:
```bash
sudo python3 port-infer-main.py --live
```

Note: The --live flag is mandatory. Without it, the script performs a cold run and does not infer active connections.

### 2. Preparing the Port File
Once the client ports are inferred, store them in a file named `port` (one port per line).
Example port file:
```python
44201
50000
60000
```

### 3. Inferring NATed Clients
#### Configuration
Edit `NATed-client-infer.py` and update the configuration:

```python
###### ---------- Configuration ----------
ATTACKER_IP = ""   # Attacker's private IP in the LAN
SERVER_IP = ""          # Target server IP
SERVER_PORT = 22               # Target server port
IFACE = "wlo1"                 # Network interface
# NAT timing parameters (router-dependent)
WAIT_AFTER_RST = 1.5      # Time for NAT to clear mapping after RST
WAIT_AFTER_SYN = 1.5      # Time to wait for server response after SYN
SYN_INTERVAL = 0      # Delay between SYN packets for a specific client (may need to be used to prevent SYN flooding)
INTER_CLIENT_DELAY = 0  
# ----------------------------------
```

Note: WAIT_AFTER_RST is NAT firmware dependent and must be determined either by:
- Inspecting router source code
- Empirical brute-force testing

### 4. Execute the attack
#### Using a Ports File
```bash
sudo ./NATed-client-infer.py --subnet-mask 24 --ports-file port
```
#### Providing Ports via CLI
```bash
sudo ./NATed-client-infer.py --subnet-mask 255.255.255.224 --default-ports 50000 60000 44201
```
