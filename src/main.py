from scanner import choose_interface, load_whitelist, scan_network, check_authorization

interface = choose_interface()

def main():
    print("[*] Cargando whitelist")
    whitelist = load_whitelist()

    print("[*] Selecciona la interfaz de red para escanear:")
    interface = choose_interface()

    print("[*] Escaneando red...")
    clients = scan_network(interface)

    unauthorized = check_authorization(clients, whitelist)

    if unauthorized:
        print("Dispositivos no autorizados detectados:")
        for device in unauthorized:
            print(f"- IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("No se detectaron dispositivos no autorizados.")

if __name__ == "__main__":
    main()
