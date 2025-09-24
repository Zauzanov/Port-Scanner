#!/usr/bin/env python3

import socket 
import sys
import argparse
import ipaddress
import sys 
import time 
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Sequence, Tuple 
import scapy.all as scapy 

scapy.conf.verb = 0

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("-i", "--iface", help="Network Interface to use", default=None)
    parser.add_argument("-t", "--target", required=True, help="Target IP or Hostname")
    parser.add_argument("-p", "--ports", required=True, help="Ports and ranges, e.g. 22,80-90,443")
    parser.add_argument("-s", "--scan-type", choices=["syn", "ack", "fin", "xmas", "tcpconnect"], default="syn", help="Scan type (default: syn)")
    parser.add_argument("-T", "--threads", type=int, default=50, help="Number of worker threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Probe timeout seconds (default: 1.0)")
    return parser.parse_args

def resolve_target(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve target '{target}: {e}") from e

def parse_ports(port_string: str) -> List[int]:
    ports = set()
    for part in port_string.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo_i = int(lo)
            hi_i = int(hi)
            if lo_i < 1 or hi_i > 65535 or lo_i > hi_i:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(lo_i, hi_i + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port number: {p}")
            ports.add(p)
    return sorted(ports)

TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
}

def syn_scan_once(iface: str, dst_ip: str, port: int, timeout: float) -> Tuple[int, str]:
    pkt = scapy.IP(dst=dst_ip) / scapy.TCP(dport=port, flags="S")
    resp = scapy.sr1(pkt, timeout=timeout, iface=iface)
    if resp is None:
        return port, "filtered/no-response"
    if resp.haslayer(scapy.TCP):
        flags =  int(resp[scapy.TCP].flags)
        if flags == (TCP_FLAGS["SYN"] | TCP_FLAGS["ACK"]):
            rst = scapy.IP(dst=dst_ip) / scapy.TCP(dport=port, flags="R")
            scapy.send(rst, verbose=False, iface=iface)
            return port, "open"
        elif flags & TCP_FLAGS["RST"]:
            return port, "closed"
    return port, "unknown"


def ack_scan_once(iface: str, dst_ip: str, port: int, timeout: float) -> Tuple[int, str]:
    pkt = scapy.IP(dst=dst_ip) / scapy.TCP(dport=port, flags="A")
    resp = scapy.sr1(pkt, timeout=timeout, iface=iface)
    if resp is None:
        return port, "Filtered"
    if resp.haslayer(scapy.TCP):
        flags = int(resp[scapy.TCP].flags)
        if flags & TCP_FLAGS["RST"]:
            return port, "unfiltered"
    return port, "unknown" 


def fin_scan_once(iface: str, dst_ip: str, port: int, timeout: float) -> Tuple[int, str]:
    pkt = scapy.IP(dst=dst_ip) / scapy.TCP(dport=port, flags="F")
    resp = scapy.sr1(pkt, timeout=timeout, iface=iface)
    if resp is None:
        return port, "open | filtered"
    if resp.haslayer(scapy.TCP):
        flags = int(resp[scapy.TCP].flags)
        if flags & TCP_FLAGS["RST"]:
            return port, "closedd"
    return port, "unknown"



def xmas_scan_once(iface: str, dst_ip: str, port: int, timeout: float) -> Tuple[int, str]:
    pkt = scapy.IP(dst=dst_ip) / scapy.TCP(dport=port, flags="FPU")
    resp = scapy.sr1(pkt, timeout=timeout, iface=iface)
    if resp is None:
        return port, "open |filtered"
    if resp.haslayer(scapy.TCP):
        flags = int(resp[scapy.TCP].flags)
        if flags & TCP_FLAGS["RST"]:
            return port, "closed"
    return port, "unknown"


def tcp_connect_once(dst_ip: str, port: int, timeout: float) -> Tuple[int, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try: 
        sock.connect((dst_ip, port))
        sock.close
        return port, "open"
    except(ConnectionRefusedError, socket.timeout):
        return port, "closed"
    except Exception as e:
        return port, f"error:{e}"
    



SCAN_FN = {
    "syn" : syn_scan_once,
    "ack" : ack_scan_once,
    "fin" : fin_scan_once,
    'xmas' : xmas_scan_once,
    "tcpconnect" : tcp_connect_once, 
}



def scan_ports_concurrent(iface: str | None, dst_ip: str, ports: Sequence[int], scan_type: str, threads: int, timeout: float) -> List[Tuple[int, str]]:
    if iface is None:
        iface = scapy.conf.iface
    
    fn = SCAN_FN[scan_type]

    results: List[Tuple[int, str]] = []
    workers = min(threads, max(1, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = []
        for p in ports:
            if scan_type == "tcpconnect":
                futures.append(ex.submit(fn, dst_ip, p, timeout))
            else:
                futures.append(ex.submit(fn, iface, dst_ip, p, timeout))
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append((-1, f"error:{e}"))
    results.sort(key=lambda x: x[0])
    return results







