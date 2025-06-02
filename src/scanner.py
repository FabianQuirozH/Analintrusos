from scapy.all import ARP, Ether, srp
import json
#aARP es para saber que dispositivos estan conectados en una red local
def load_whitelist(path="src/whitelist.json"):
    #aqui lee la lista blanca y devuelve un diccionario de MAC:NOMBRE
    with open(path, 'r') as f:
        return json.load(f)

def scan_network(interface="Ethernet"):
    ip_range = "192.168.1.0/24"
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})
    return clients

def check_authorization(clients, whitelist):
    #COMPARA LOS DISPOSITIVOS CON LA LISTA BLANCA
    authorized_macs = [entry['mac'].lower() for entry in whitelist]
    unauthorized = []
    for device in clients:
        if device['mac'].lower() not in authorized_macs:
            unauthorized.append(device)
    return unauthorized
