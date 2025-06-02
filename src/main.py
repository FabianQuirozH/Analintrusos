from scanner import scan_network, check_authorization, load_whitelist
import datetime
import os

def log_report(devices):
    now = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs("logs", exist_ok=True)
    with open(f"logs/scan_report_{now}.log", "w") as f:
        for d in devices:
            f.write(f"{d['ip']} - {d['mac']}\n")

def main():
    print("[*] Cargando whitelist")
    whitelist = load_whitelist()
    
    print("[*] Escaneando red")
    clients = scan_network()
    
    print("[*] Verificando dispositivos no autorizados")
    unauthorized = check_authorization(clients, whitelist)
    
    if unauthorized:
        print("[!] Dispositivos NO autorizados detectados:")
        for d in unauthorized:
            print(f"    - IP: {d['ip']}, MAC: {d['mac']}")
    else:
        print("[+] Todos los dispositivos están autorizados.")
    
    log_report(clients)

if __name__ == "__main__":
    main()
