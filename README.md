# TCP Connection Inference Behind NAT

This project performs TCP connection inference and hijacking attacks behind a NAT.
There are two steps to the attack:
1. Inferring client-side ephemeral ports in use in the NAT (port preservation)
2. Inferring NATed clients communicating with a target server

## Prerequisites
### System Requirements
- Linux (tested Ubuntu 24.02)
- Root access (required for raw packet injection)

### Dependencies
#### Scapy (Required for the Python scripts)
```bash
sudo apt update
sudo apt install python3-scapy
```
#### C++ port inference (Required for port_infer)
The fast port inference tool is written in C++ and needs a compiler, make, and libtins.
```bash
sudo apt update
sudo apt install g++ make libtins-dev libpcap-dev
```
If your distro does not package libtins-dev, build it from source: https://github.com/mfontanini/libtins

## 1. Inferring Client Ports in Use (fast, C++)
This is the recommended tool for step 1. It is a C++ reimplementation of `port-infer-main.py` and is much faster.

### Build
```bash
make
```
This produces the `port_infer` binary.

### Configuration
The defaults live in the CONFIG block at the top of `port_infer.cpp`. You can edit them there, or override any value on the command line. Run `./port_infer -h` for the full list:
```
-a attacker_ip    Attacker's private IP inside NAT
-s server_ip      Target server IP
-p server_port    Target server port
-n nat_ip         NAT public IP
-i iface          Network interface
-S start_port     Ephemeral port range start
-E end_port       Ephemeral port range end
-r rounds         Confirmation rounds a port must miss to count as in-use
-b batch          Ports per batch (small bursts keep packet loss low)
-g send_gap_us    Inter-packet spacing while sending
-c settle_us      Gap between SYN and SYN/ACK within a batch
-w wait_us        Drain wait after the last batch each round
-t ttl_syn        TTL of the probe SYN (must die before the server)
-T ttl_synack     TTL of the crafted SYN/ACK (must reach the NAT)
-d                Dump the first crafted SYN and SYN/ACK, then exit (no send)
```

### Run
```bash
sudo ./port_infer
```
Ports that never return a SYN/ACK across all rounds are reported as in use by another client.

### Tuning notes
- `-t ttl_syn` must be low enough that the probe SYN dies before reaching the server, but high enough to pass the NAT and create a mapping. Set it from your hop count to the NAT. If it is wrong, every result is unreliable.
- If you see many false positives, the SYN/ACK replies are being lost. Lower `-b` or raise `-g` to reduce burst loss, and check the round-by-round "still missing" counts print. They should shrink fast.
- Use `-d` to sanity check the crafted packets without sending anything.

## 1b. Inferring Client Ports in Use (Python, reference)
### Configuration
Edit `port-infer-main.py` and fill in the configuration section:

###### ---------- CONFIG ----------
 ```python
IFACE = "wlo1"                 # Network interface
START_PORT = 32768             # Ephemeral port range start
END_PORT = 65535               # Ephemeral port range end
attacker_ip = "192.168.0.10"   # Attacker's private IP inside NAT
server_ip = "4.4.4.4"          # Target server IP
SERVER_PORT = 22               # Target server port
nat_ip = "6.6.6.6"             # NAT public IP
```

Run the script in live mode:
```bash
sudo python3 port-infer-main.py --live
```

Note: The --live flag is mandatory. Without it, the script performs a cold run and does not infer active connections.

## 2. Preparing the Port File
Once the client ports are inferred, store them in a file named port (one port per line).
Example port file:
```python
44201
50000
60000
```

## 3. Inferring NATed Clients
### Configuration
Edit `NATed_client_infer.py` and update the configuration:

```python
###### ---------- Configuration ----------
ATTACKER_IP = "192.168.0.10"   # Attacker's private IP in the LAN
SERVER_IP = "4.4.4.4"          # Target server IP
SERVER_PORT = 22               # Target server port
IFACE = "wlo1"                 # Network interface
# NAT timing parameters (router-dependent)
WAIT_AFTER_RST = 11.0          # Time for NAT to clear mapping after RST
WAIT_AFTER_SYN = 2.0           # Additional wait after SYN
INTER_PROBE_DELAY = 1.0        # Delay between testing different clients
# ----------------------------------
```

Note: WAIT_AFTER_RST is NAT firmware dependent and must be determined either by:
- Inspecting router source code
- Empirical brute-force testing

## 4. Execute
### Using a Ports File
```bash
sudo ./NATed_client_infer.py --subnet-mask 24 --ports-file port
```
### Providing Ports via CLI
```bash
sudo ./NATed_client_infer.py --subnet-mask 255.255.255.224 --default-ports 50000 60000 44201
```
