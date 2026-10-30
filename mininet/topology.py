#!/usr/bin/env python3
"""
mininet/topology.py — Mininet DDoS Simulation Topology
======================================================
Builds an SDN network for testing DDoS attacks and mitigation:
  - 1 Open vSwitch (s1)
  - 1 Web Server Victim (h1: 10.0.0.1)
  - 1 Legitimate Client  (h2: 10.0.0.2)
  - 2 Attacker Bots      (h3: 10.0.0.3, h4: 10.0.0.4)

Usage (Linux / WSL2):
    sudo python3 mininet/topology.py
"""

import sys
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def build_and_run():
    net = Mininet(controller=Controller, switch=OVSSwitch)

    info("*** Step 1: Adding Controller\n")
    net.addController("c0")

    info("*** Step 2: Adding Open vSwitch (s1)\n")
    s1 = net.addSwitch("s1", failMode="standalone")

    info("*** Step 3: Adding Virtual Hosts\n")
    # h1 is the Victim Web Server
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    # h2 is the Legitimate Client
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    # h3 and h4 are Attacker Bots
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

    info("*** Step 4: Connecting Hosts to Open vSwitch\n")
    net.addLink(h1, s1)  # Port 1: s1-eth1 -> h1
    net.addLink(h2, s1)  # Port 2: s1-eth2 -> h2
    net.addLink(h3, s1)  # Port 3: s1-eth3 -> h3
    net.addLink(h4, s1)  # Port 4: s1-eth4 -> h4

    info("*** Step 5: Starting Network\n")
    net.start()

    # Launch HTTP server on Victim (h1)
    info("*** Starting Python HTTP Server on h1 (Port 80)...\n")
    h1.cmd("python3 -m http.server 80 &")

    print("\n" + "=" * 62)
    print("  MININET DDoS TESTBED READY!")
    print("=" * 62)
    print("  Victim Server     : h1 (10.0.0.1:80)")
    print("  Legitimate Client : h2 (10.0.0.2)")
    print("  Attacker Bots     : h3 (10.0.0.3), h4 (10.0.0.4)")
    print("  Switch Interface  : s1-eth1 (mirrors/receives victim packets)")
    print("=" * 62 + "\n")

    CLI(net)

    info("*** Stopping Network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build_and_run()

