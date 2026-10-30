#!/usr/bin/env python3
"""
mininet/collector.py — Live Traffic Feature Extractor & OpenFlow Mitigator
=========================================================================
Sniffs real packets flowing through switch interface 's1-eth1',
aggregates packets by source IP over 1-second sliding windows, extracts
the exact 10 statistical flow features, runs inference with the ML model,
and dynamically injects OpenFlow drop rules into Open vSwitch.

Usage (Linux / WSL2):
    sudo python3 mininet/collector.py
"""

import os
import sys
import time
import math
import collections
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Ensure backend modules can be imported
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))

from ml_detector import MLDetector
from anomaly_detector import AnomalyDetector

# Configuration
INTERFACE   = "s1-eth1"   # Switch link connected to Victim (h1)
SWITCH_NAME = "s1"
WINDOW_SEC  = 1.0         # 1 second sliding aggregation window

# Load ML detectors
print("[*] Loading trained machine learning models...")
ml_detector = MLDetector()
ml_detector.load()

anomaly_detector = AnomalyDetector()
anomaly_detector.load()
print("[OK] Models loaded successfully.\n")

# Packet buffer: src_ip -> list of packet objects
packet_buffer = collections.defaultdict(list)
last_flush_time = time.time()
blocked_ips = set()


def calculate_entropy(probabilities):
    """Compute Shannon entropy."""
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def extract_features_from_window(packets, elapsed_seconds):
    """
    Extract the 10 flow features matching the model training dataset:
      [pkt_rate, byte_rate, avg_pkt_size, syn_ratio, udp_ratio,
       icmp_ratio, unique_dports, flow_duration, ttl_avg, flag_entropy]
    """
    total_pkts = len(packets)
    if total_pkts == 0:
        return None

    total_bytes = sum(len(p) for p in packets)
    avg_pkt_size = total_bytes / total_pkts
    pkt_rate = total_pkts / max(elapsed_seconds, 0.001)
    byte_rate = total_bytes / max(elapsed_seconds, 0.001)

    syn_pkts = 0
    udp_pkts = 0
    icmp_pkts = 0
    destination_ports = set()
    ttl_values = []
    flag_counts = collections.defaultdict(int)

    for pkt in packets:
        if pkt.haslayer(IP):
            ttl_values.append(pkt[IP].ttl)

        if pkt.haslayer(TCP):
            flag_val = int(pkt[TCP].flags)
            flag_counts[flag_val] += 1
            destination_ports.add(pkt[TCP].dport)
            if flag_val == 0x02:  # Pure SYN flag
                syn_pkts += 1
        elif pkt.haslayer(UDP):
            udp_pkts += 1
            destination_ports.add(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            icmp_pkts += 1

    # Flag entropy calculation
    probs = [c / total_pkts for c in flag_counts.values()]
    flag_entropy = calculate_entropy(probs) if probs else 0.0

    return {
        "pkt_rate": round(pkt_rate, 2),
        "byte_rate": round(byte_rate, 2),
        "avg_pkt_size": round(avg_pkt_size, 2),
        "syn_ratio": round(syn_pkts / total_pkts, 3),
        "udp_ratio": round(udp_pkts / total_pkts, 3),
        "icmp_ratio": round(icmp_pkts / total_pkts, 3),
        "unique_dports": len(destination_ports),
        "flow_duration": round(elapsed_seconds, 2),
        "ttl_avg": round(sum(ttl_values) / len(ttl_values), 1) if ttl_values else 64.0,
        "flag_entropy": round(flag_entropy, 3),
    }


def block_ip_in_ovs(ip_address):
    """Inject an OpenFlow drop rule into Open vSwitch."""
    if ip_address in blocked_ips:
        return

    cmd = [
        "ovs-ofctl", "add-flow", SWITCH_NAME,
        f"priority=50000,ip,nw_src={ip_address},actions=drop"
    ]
    try:
        subprocess.run(cmd, check=True)
        blocked_ips.add(ip_address)
        print(f"\n[🛡️ MITIGATION ACTIVATED] OpenFlow DROP flow installed on {SWITCH_NAME} for IP: {ip_address}")
        print(f"[*] All subsequent packets from {ip_address} are dropped at the switch!\n")
    except Exception as ex:
        print(f"[ERROR] Could not install OpenFlow rule: {ex}")


def process_packet(pkt):
    global last_flush_time

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        packet_buffer[src_ip].append(pkt)

    now = time.time()
    elapsed = now - last_flush_time

    if elapsed >= WINDOW_SEC:
        for src_ip, pkts in list(packet_buffer.items()):
            # Only evaluate active sources
            if len(pkts) < 5:
                continue

            features = extract_features_from_window(pkts, elapsed)
            if not features:
                continue

            # 1. Supervised prediction
            ml_res = ml_detector.predict(features)
            # 2. Anomaly scoring
            anom_res = anomaly_detector.score(features)

            label = ml_res["label"]
            conf = ml_res["confidence"]
            anom_score = anom_res["anomaly_score"]

            print(
                f"[{time.strftime('%H:%M:%S')}] IP: {src_ip:<15} | "
                f"Rate: {features['pkt_rate']:>7.1f} pkt/s | "
                f"ML: {label:<10} ({conf*100:.0f}%) | "
                f"Anomaly: {anom_score*100:.0f}%"
            )

            # High-confidence attack or anomaly -> trigger OpenFlow drop
            if (label != "normal" and conf >= 0.85) or anom_score >= 0.70:
                print(f"🚨 [ATTACK DETECTED] Source: {src_ip} | Type: {label} | Conf: {conf*100:.0f}%")
                block_ip_in_ovs(src_ip)

        packet_buffer.clear()
        last_flush_time = now


if __name__ == "__main__":
    print(f"[*] Listening on virtual interface: {INTERFACE} ...")
    print("[*] Monitoring network flows in real time. Press Ctrl+C to stop.\n")
    try:
        sniff(iface=INTERFACE, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\nStopping collector.")

