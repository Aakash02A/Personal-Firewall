from scapy.all import sniff, IP, TCP, UDP
import datetime
import threading
import os

# Use sets for performance and to avoid duplicates
blocked_ips = set()
blocked_ports = set()

log_file_path = "logs/traffic_log.txt"
running = False

def log_packet(pkt, status):
    try:
        with open(log_file_path, "a", encoding="utf-8") as f:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else "-"
            dst_port = pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else "-"
            proto = pkt.proto
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {status} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Proto: {proto}\n")
    except Exception as e:
        print(f"Error logging packet: {e}")

def process_packet(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dport = pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else None
        status = "[BLOCKED]" if src_ip in blocked_ips or (dport and dport in blocked_ports) else "[ALLOWED]"
        log_packet(pkt, status)

def start_sniffing():
    global running
    running = True
    sniff(filter="ip", prn=process_packet, store=0, stop_filter=lambda _: not running)

def stop_sniffing():
    global running
    running = False

def start_firewall():
    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()
