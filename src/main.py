from scanner import select_interface, load_whitelist, scan_network, check_authorization

def main():
    print("[*] Cargando whitelist")
    whitelist = load_whitelist()

    print("[*] Selecciona la interfaz de red para escanear:")
    interface = select_interface()
    print(f"[*] Interfaz seleccionada: {interface}")

    print("[*] Escaneando la red...")
    clients = scan_network(interface)

    print(f"[*] Dispositivos detectados en la red: {len(clients)}")

    unauthorized = check_authorization(clients, whitelist)
    print(f"[*] Dispositivos no autorizados encontrados: {len(unauthorized)}")

    if unauthorized:
        print("\nLista de dispositivos no autorizados:")
        for device in unauthorized:
            print(f"- IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("No se detectaron dispositivos no autorizados. ¡Red limpia!")

if __name__ == "__main__":
    main()
