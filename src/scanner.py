from scapy.all import ARP, Ether, srp, get_if_list, get_if_addr
import json

def list_interfaces():
    interfaces = get_if_list()
    print("[*] Interfaces detectadas:")
    for i, iface in enumerate(interfaces):
        ip = None
        try:
            ip = get_if_addr(iface)
            if ip == '0.0.0.0' or ip.startswith('127.'):
                ip = None
        except Exception:
            ip = None

        if ip:
            print(f"{i}: {iface} - IP: {ip}")
        else:
            print(f"{i}: {iface} - IP: No asignada")

def choose_interface():
    list_interfaces()
    while True:
        try:
            choice = int(input("Selecciona el número de la interfaz a usar: "))
            interfaces = get_if_list()
            if 0 <= choice < len(interfaces):
                selected_iface = interfaces[choice]
                print(f"Interfaz seleccionada: {selected_iface}")
                return selected_iface
            else:
                print("Número inválido, intenta de nuevo.")
        except ValueError:
            print("Por favor ingresa un número válido.")

def load_whitelist(path="src/whitelist.json"):
    with open(path, 'r') as f:
        return json.load(f)

def scan_network(interface=None):
    if not interface:
        interface = choose_interface()

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
    authorized_macs = [entry['mac'].lower() for entry in whitelist]
    unauthorized = []
    for device in clients:
        if device['mac'].lower() not in authorized_macs:
            unauthorized.append(device)
    return unauthorized

# --- En main.py o bloque principal ---
if __name__ == "__main__":
    print("[*] Cargando whitelist")
    whitelist = load_whitelist()
    print("[*] Escaneando red")
    interface = choose_interface()   # Esto muestra la lista y permite elegir interfaz
    clients = scan_network(interface)
    unauthorized = check_authorization(clients, whitelist)

    print("\n--- Resultados ---")
    print(f"Dispositivos encontrados: {len(clients)}")
    print(f"Dispositivos no autorizados: {len(unauthorized)}")
    for device in unauthorized:
        print(f" - IP: {device['ip']} - MAC: {device['mac']}")
