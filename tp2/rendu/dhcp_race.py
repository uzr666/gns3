from scapy.all import *

def repond_au_client(packet):

    if DHCP not in packet:
        return

    type_message = packet[DHCP].options[0][1]

    # discover
    if type_message == 1:
        print("discover recue, envoie de l'offer...")
        reponse = "offer"

    # request
    elif type_message == 3:
        print("request recue, envoie de l'ack...")
        reponse = "ack"
    else:
        return

    trame  = Ether(dst="ff:ff:ff:ff:ff:ff")
    paquet = IP(src="10.1.20.82", dst="255.255.255.255")
    udp    = UDP(sport=67, dport=68)
    bootp  = BOOTP(op=2, yiaddr="10.1.20.222", xid=packet[BOOTP].xid, chaddr=packet[BOOTP].chaddr)
    dhcp = DHCP(options=[("message-type", reponse), ("server_id","10.1.20.82"), ("subnet_mask","255.255.255.0"), ("router","10.1.20.254"), ("name_server","1.1.1.1"), ("lease_time",3600), "end"])

    trame_finale = trame/paquet/udp/bootp/dhcp

    sendp(trame_finale, iface="eth0", verbose=0)
    print("envoyé !")

print("DHCP démarré, en attente d'un discover...")
sniff(filter="udp and port 67 and not src host 10.1.20.82", prn=repond_au_client, iface="eth0")