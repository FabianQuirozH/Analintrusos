# Analintrusos🕵️‍♂️

Proyecto local de escaneo de red para detección de dispositivos no autorizados, 100% compatible con legislación chilena.

---

## ⚙️ Requisitos del sistema

Este proyecto usa `scapy` para detectar dispositivos conectados a la red local a través de paquetes ARP.

### Dependencias

- Python 3.10 o superior
- Scapy (se instala automáticamente con `requirements.txt`)
- Sistema operativo: Windows

### 🛠️ Requisito especial en Windows

Para poder escanear correctamente la red en sistemas Windows, es obligatorio instalar **Npcap**, ya que `scapy` necesita acceso al nivel 2 de red (Layer 2).

🔗 Descarga oficial: [https://npcap.com/#download](https://npcap.com/#download)

Durante la instalación, asegúrate de marcar la opción:

> ✅ “Install Npcap in WinPcap API-compatible Mode”

⚠️ Si no lo instalas, al ejecutar el script obtendrás un error



## Instalación

```bash
git clone https://github.com/FabianQuirozH/Analintrusos.git
```
```bash
cd Analintrusos
```
```bash
python -m venv env
```
```bash
source env/Scripts/activate  # En Windows
```
```bash
pip install -r requirements.txt
```
```bash
python src/main.py 
```
