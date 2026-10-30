# Mininet SDN Testbed for DDoS Detection & Prevention

This directory contains the integration scripts to run the DDoS Detection and Prevention system on a **real virtual Software-Defined Network (SDN)** using [Mininet](http://mininet.org/) and [Open vSwitch](https://www.openvswitch.org/).

---

## 🏗️ Architecture

```
                 +-----------------------+
                 | Open vSwitch (s1)     |
                 +-----------------------+
                   /        |         \
                  /         |          \
                 /          |           \
     +--------------+  +----------+  +--------------------+
     | Victim Server|  | Normal   |  | Attacker Bots      |
     | h1 (10.0.0.1)|  | Client   |  | h3 (10.0.0.3)      |
     | Port 80 HTTP |  | h2       |  | h4 (10.0.0.4)      |
     |              |  |(10.0.0.2)|  | (hping3 flooders)  |
     +--------------+  +----------+  +--------------------+
```

- **Open vSwitch (`s1`)**: Virtual OpenFlow-capable software switch.
- **Victim (`h1`)**: Runs a Python HTTP server on port 80.
- **Normal Client (`h2`)**: Periodically performs legitimate `curl` requests.
- **Attackers (`h3`, `h4`)**: Launch actual volumetric floods using `hping3`.
- **`collector.py`**: Sniffs `s1-eth1`, computes the 10 flow features, runs the Random Forest and Isolation Forest models, and dynamically installs `actions=drop` rules into `s1`.

---

## 📋 Prerequisites (Linux / Ubuntu / WSL2)

Mininet requires a Linux environment:
- Ubuntu 20.04 / 22.04 LTS (native, dual-boot, or in VirtualBox / VMware)
- Or Windows Subsystem for Linux 2 (WSL2) with systemd enabled.

### Install packages:
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-pip hping3 curl net-tools
pip3 install scapy scikit-learn pandas numpy
```

---

## 🚀 How to Run the Mininet Testbed

### Step 1 — Start the Topology
In **Terminal 1**:
```bash
sudo python3 mininet/topology.py
```
This boots Open vSwitch, sets up the virtual interfaces, starts the web server on `h1`, and opens the `mininet>` prompt.

---

### Step 2 — Start the ML Sniffer & OpenFlow Mitigator
In **Terminal 2**:
```bash
sudo python3 mininet/collector.py
```
You will see it load the ML models and start sniffing live traffic on `s1-eth1`.

---

### Step 3 — Send Normal Legitimate Traffic
In **Terminal 1** (`mininet>` prompt):
```bash
mininet> h2 curl -I http://10.0.0.1
```
Output:
```text
HTTP/1.0 200 OK
```
In Terminal 2, you will observe the flow classified as `normal` with low packet rate.

---

### Step 4 — Launch a DDoS Attack
In **Terminal 1** (`mininet>` prompt), command attacker `h3` to flood port 80:
```bash
mininet> h3 hping3 -S -p 80 --flood 10.0.0.1
```

Watch **Terminal 2**:
1. Within 1 second, the packet rate spikes to thousands of packets/sec.
2. The Random Forest model flags `syn_flood` with `100%` confidence.
3. The mitigation engine triggers:
   ```text
   [🛡️ MITIGATION ACTIVATED] OpenFlow DROP flow installed on s1 for IP: 10.0.0.3
   ```
4. All packets from `10.0.0.3` are dropped at the switch!

---

### Step 5 — Verify Legitimate Client Access Is Preserved
While `h3` is still attacking, test client `h2` again in **Terminal 1**:
```bash
mininet> h2 curl -I http://10.0.0.1
```
Result:
```text
HTTP/1.0 200 OK
```
The victim web server responds instantly because the attacker's traffic is dropped before it reaches the victim!

---

### Step 6 — Cleanup
To stop the attack, press `Ctrl + C` in Terminal 1, then type:
```bash
mininet> exit
```
To clear any remaining virtual interfaces:
```bash
sudo mn -c
```

