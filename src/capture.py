import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import argparse
import re
from datetime import datetime as dt
from scapy.all import sniff, DNS, IP, TCP, UDP

def parse_http(raw_payload):
    """
    Attempt to parse an HTTP GET or POST request.
    Returns a tuple (method, host, uri) if found; otherwise, returns None.
    """
    try:
        text = raw_payload.decode("utf-8", errors="ignore")
    except Exception:
        return None
   
    if text.startswith("GET ") or text.startswith("POST "):
        lines = text.splitlines()
        if not lines:
            return None
        parts = lines[0].split()
        if len(parts) < 3:
            return None
        method = parts[0]
        uri = parts[1]
        host = "Unknown"
        
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return method, host, uri
    return None

def parse_tls(raw_payload):
    """
    Attempt to parse a TLS Client Hello message from the raw payload.
    Returns the SNI hostname if found; otherwise, returns None.
    """
    if len(raw_payload) < 6:
        return None
    if raw_payload[0] != 22:
        return None
    if raw_payload[5] != 1:
        return None
    try:
        index = 5 + 4  
        index += 2 + 32  
        if index >= len(raw_payload):
            return None
        session_id_len = raw_payload[index]
        index += 1 + session_id_len  
        if index + 2 > len(raw_payload):
            return None
        cs_len = int.from_bytes(raw_payload[index:index+2], "big")
        index += 2 + cs_len  
        if index >= len(raw_payload):
            return None
        comp_len = raw_payload[index]
        index += 1 + comp_len  
        if index + 2 > len(raw_payload):
            return None
        ext_total_len = int.from_bytes(raw_payload[index:index+2], "big")
        index += 2
        end_index = index + ext_total_len
        while index + 4 <= end_index:
            ext_type = int.from_bytes(raw_payload[index:index+2], "big")
            ext_len = int.from_bytes(raw_payload[index+2:index+4], "big")
            index += 4
            if ext_type == 0:  
                if index + 2 > len(raw_payload):
                    return None
               
                index += 2
                if index + 3 > len(raw_payload):
                    return None
                name_type = raw_payload[index]
                name_len = int.from_bytes(raw_payload[index+1:index+3], "big")
                index += 3
                if index + name_len > len(raw_payload):
                    return None
                server_name = raw_payload[index:index+name_len].decode("utf-8", errors="ignore")
                return server_name
            else:
                index += ext_len
    except Exception:
        return None
    return None

def parse_dns(raw_payload):
    """
    Attempt to parse a DNS query from the raw payload.
    Returns the queried name (for an A-record request) if valid; otherwise, returns None.
    """
    if len(raw_payload) < 12:
        return None
    try:
        dns_pkt = DNS(raw_payload)
        if dns_pkt.qr == 0 and dns_pkt.qdcount > 0:
            if dns_pkt.qd.qtype != 1:
                return None
            qname = dns_pkt.qd.qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            if qname.endswith('.'):
                qname = qname[:-1]
            if not re.match(r'^[A-Za-z0-9.-]+$', qname):
                return None
            if qname and '.' in qname:
                return qname
    except Exception:
        return None
    return None

def process_packet(packet):
    """
    Process each captured packet:
    - Extract timestamp, source/destination IP and ports.
    - For TCP packets, attempt HTTP then TLS parsing.
    - For UDP packets, attempt DNS parsing.
    """
    if not packet.haslayer(IP):
        return

    timestamp = dt.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    src_port = "?"
    dst_port = "?"
    raw_payload = b""

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        raw_payload = bytes(tcp.payload)
        http_result = parse_http(raw_payload)
        if http_result:
            method, host, uri = http_result
            print(f"{timestamp} HTTP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {host} {method} {uri}")
            return
        
        tls_result = parse_tls(raw_payload)
        if tls_result:
            print(f"{timestamp} TLS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {tls_result}")
            return
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        raw_payload = bytes(udp.payload)
        dns_result = parse_dns(raw_payload)
        if dns_result:
            print(f"{timestamp} DNS {src_ip}:{src_port} -> {dst_ip}:{dst_port} {dns_result}")
            return

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to capture from", default="eth0")
    parser.add_argument("-r", "--read", help="Read packets from a pcap file")
    parser.add_argument("expression", nargs="?", default="", help="BPF filter expression")
    args = parser.parse_args()

    bpf_filter = args.expression.strip() if args.expression.strip() else None

    if args.read:
        print(f"Reading from pcap file: {args.read}")
        sniff(offline=args.read, prn=process_packet, store=False, filter=bpf_filter)
    else:
        print(f"Sniffing on interface: {args.interface}")
        sniff(iface=args.interface, prn=process_packet, store=False, filter=bpf_filter)

if __name__ == "__main__":
    main()
