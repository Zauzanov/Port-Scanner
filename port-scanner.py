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