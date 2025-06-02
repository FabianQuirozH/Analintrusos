from scapy.all import ARP, Ether, srp, get_if_list
import json

def get_friendly_interfaces():
    interfaces = get_if_list()
    friendly = []
    for iface in interfaces:
        lname = iface.lower()
        if "wi-fi" in lname or "wireless" in lname:
            friendly.append((iface, "Wi-Fi"))
        elif "ethernet" in lname:
            friendly.append((iface, "Ethernet"))
        elif "loopback" in lname or "npf_loopback" in lname:
            friendly.append((iface, "Loopback"))
    return friendly

def select_interface():
    friendly = get_friendly_interfaces()
    if not friendly:
        print("No se encontraron interfaces Wi-Fi, Ethernet o Loopback. Mostrando todas:")
        friendly = [(iface, iface) for iface in get_if_list()]
    print("[*] Interfaces disponibles:")
    for i, (iface, name) in enumerate(friendly):
        print(f"{i}: {name} ({iface})")
    while True:
        try:
            choice = int(input("Selecciona el número de la interfaz a usar: "))
            if 0 <= choice < len(friendly):
                return friendly[choice][0]
            else:
                print(f"Por favor ingresa un número entre 0 y {len(friendly)-1}")
        except ValueError:
            print("Entrada inválida. Por favor ingresa un número.")

def load_whitelist(path="src/whitelist.json"):
    # Lee la lista blanca y devuelve un diccionario de MAC:NOMBRE
    with open(path, 'r') as f:
        return json.load(f)

def scan_network(interface):
    ip_range = "192.168.1.0/24"
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})
    return clients

def check_authorization(clients, whitelist):
    # Compara los dispositivos con la lista blanca
    authorized_macs = [entry['mac'].lower() for entry in whitelist]
    unauthorized = []
    for device in clients:
        if device['mac'].lower() not in authorized_macs:
            unauthorized.append(device)
    return unauthorized


if __name__ == "__main__":
    print("[*] Interfaces detectadas por Scapy:")
    interface = select_interface()
    print(f"[*] Interfaz seleccionada: {interface}")

    print("[*] Cargando whitelist")
    whitelist = load_whitelist()

    print("[*] Escaneando red")
    clients = scan_network(interface)

    unauthorized = check_authorization(clients, whitelist)

    print(f"Dispositivos detectados: {len(clients)}")
    print(f"Dispositivos no autorizados: {len(unauthorized)}")
    for d in unauthorized:
        print(f"- IP: {d['ip']}, MAC: {d['mac']}")
