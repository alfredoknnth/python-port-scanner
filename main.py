import sys
import socket
import threading
from scapy.all import *

def scan_port_tcp(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"[+] Port {port} are open!")

def scan_ports_tcp(target, ports):
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port_tcp, args=(target,port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def scan_port_udp(target, port):
    if(port == 53): # DNS payload
        payload = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
    elif(port == 123): # NTP payload
        payload = b'\x1b' + 47 * b'\0'
    elif(port == 161): #SNMP payload
        payload = b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x71\x41\xcd\x0d\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
    else:
        payload = b''

    packet = IP(dst=target) / UDP(dport=port) / Raw(load=payload)
    res = sr1(packet, timeout=60, verbose=False)

    if res is None:
        pass
    elif res.haslayer(ICMP):
        type = res.getlayer(ICMP).type
        code = res.getlayer(ICMP).code
        if type == 3 and code == 3:
            pass
        else: pass
    else:
        print(f"[+] Port {port} are open!")

def scan_ports_udp(target, ports):
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port_udp, args=(target,port))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

def os_detect(target):
    packet = IP(dst=target) / ICMP()
    res = sr1(packet, timeout=2, verbose=False)

    if(res):
        ttl = res.ttl
        if ttl == 64:
            print("[OS Detection] Target using Linux/Unix")
        elif ttl == 128:
            print("[OS Detection] Target using Windows")
        elif ttl == 255:
            print("[OS Detection] Sistem using Cisco IOS")
        else:
            print("[OS Detection] Failed to fetch OS info")

i = 1
protocol = 'tcp'
while i <= (len(sys.argv)-1):
    if(sys.argv[i] == '-i'):
        target = sys.argv[i+1]
        i+=1
    elif(sys.argv[i] == '-sU'):
        protocol = 'udp'
        i+=1
    elif(sys.argv[i] == '-OS'):
        os_scan = True
        i+=1
    else:
        pass
    i+=1
if(protocol == 'tcp'):
    scan_ports_tcp(target, range(1,65536)) #change the range for faster scan but less accurate
elif(protocol == 'udp'):
    scan_ports_udp(target,range(1,1000)) #change the range for faster scan but less accurate
else:
    print("Unexpected error")
if(os_scan == True): #os detection trigger
    os_detect(target)