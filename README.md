# 🚀 Quick Start
## 1. Download 'port-scanner.py' file

## 2. Open the manual:

```bash
python port-scanner.py -h
python3 port-scanner.py -h
```
It looks like this:
```bash
usage: port-scanner.py [-h] [-i IFACE] -t TARGET -p PORTS
                       [-s {syn,ack,fin,xmas,tcpconnect}] [-T THREADS]
                       [--timeout TIMEOUT]

Port Scanner

options:
  -h, --help            show this help message and exit
  -i, --iface IFACE     Network Interface to use
  -t, --target TARGET   Target IP or Hostname
  -p, --ports PORTS     Ports and ranges, e.g. 22,80-90,443
  -s, --scan-type {syn,ack,fin,xmas,tcpconnect}
                        Scan type (default: syn)
  -T, --threads THREADS
                        Number of worker threads (default: 50)
  --timeout TIMEOUT     Probe timeout seconds (default: 1.0)
```

## 3. Example of a command:
```bash
python port-scanner.py -t 192.168.204.129 -p 20-30 -s tcpconnect
```

## 4. Also you can make it executable like this 
```bash
chmod +x port-scanner.py
```
## and run directly:
```bash
./port-scanner.py -h
```
## 5. For raw packets(xmas, ack, syn...) you need root privileges:  
```bash
sudo ./port-scanner.py -t 192.168.204.129 -p 20-30 
```
## for tcpconnect:
```bash 
./port-scanner.py -t 192.168.204.129 -p 20-30 -s tcpconnect
```

# Demo:
```bash
sudo ./port-scanner.py -t 192.168.204.129 -p 20-30 -s xmas
ATTENTION: only scan systems you own or have permission to test!
Scanning 192.168.204.129 ports=11 type=xmas iface=eth0
/usr/lib/python3/dist-packages/scapy/sendrecv.py:726: SyntaxWarning: 'iface' has no effect on L3 I/O sr1(). For multicast/link-local see https://scapy.readthedocs.io/en/latest/usage.html#multicast
  warnings.warn(
   20 closed
   21 open |filtered
   22 open |filtered
   23 open |filtered
   24 closed
   25 open |filtered
   26 closed
   27 closed
   28 closed
   29 closed
   30 closed
Done in 1.23s

```
