import subprocess
import sys

def install_dependencies():
    """Ejecuta requirements.py para instalar dependencias"""
    try:
        subprocess.run([sys.executable, "requirements.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al instalar dependencias: {e}")
        sys.exit(1)

# Verifica e instala dependencias antes de continuar
install_dependencies()

print("Todas las dependencias están instaladas. Iniciando NetSecTools...")
import tkinter as tk
from tkinter import ttk, messagebox
import socket
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp
import netifaces
import socket

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
import nmap

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
    
def open_port_scanner(ip):
    """Escanea los puertos de una IP y muestra los resultados."""
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    
    # Escanear puertos
    start_port = 1
    end_port = 1024  # Rango de puertos a escanear
    open_ports = scan_ports(ip, start_port, end_port)
    
    if open_ports:
        result_text = f"Puertos abiertos en {ip}:\n{', '.join(map(str, open_ports))}"
        
        # Mostrar el resultado con la opción de descargar
        mostrar_resultado_con_descarga(
            titulo="Escaneo de Puertos",
            mensaje=result_text,
            nombre_archivo=f"escaneopuertos_{ip}.txt"
        )
    else:
        messagebox.showinfo("Escaneo de Puertos", f"No se encontraron puertos abiertos en {ip}.")

def mostrar_resultado_con_descarga(titulo, mensaje, nombre_archivo):
    """
    Muestra una ventana de mensaje con dos botones: "Salir" y "Descargar y Salir".
    Si se hace clic en "Descargar y Salir", se crea un archivo .txt con el mensaje.
    
    :param titulo: Título de la ventana.
    :param mensaje: Mensaje a mostrar en la ventana.
    :param nombre_archivo: Nombre del archivo .txt a crear.
    """
    def descargar_y_salir():
        # Crear el archivo .txt
        with open(nombre_archivo, "w", encoding="utf-8") as archivo:
            archivo.write(mensaje)
        ventana.destroy()  # Cerrar la ventana

    def salir():
        ventana.destroy()  # Cerrar la ventana sin hacer nada

    # Crear una ventana personalizada
    ventana = tk.Toplevel()
    ventana.title(titulo)
    
    # Mostrar el mensaje
    mensaje_label = tk.Label(ventana, text=mensaje, font=("Helvetica", 12), padx=20, pady=20)
    mensaje_label.pack()

    # Crear los botones
    boton_descargar = tk.Button(ventana, text="Descargar y Salir", command=descargar_y_salir, bg="#4CAF50", fg="white")
    boton_descargar.pack(side=tk.LEFT, padx=10, pady=10)

    boton_salir = tk.Button(ventana, text="Salir", command=salir, bg="#FF5722", fg="white")
    boton_salir.pack(side=tk.RIGHT, padx=10, pady=10)

    # Centrar la ventana en la pantalla
    ventana.update_idletasks()
    ancho = ventana.winfo_width()
    alto = ventana.winfo_height()
    x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    y = (ventana.winfo_screenheight() // 2) - (alto // 2)
    ventana.geometry(f"{ancho}x{alto}+{x}+{y}")

    # Hacer que la ventana sea modal
    ventana.grab_set()
    ventana.wait_window()

def scan_network(ip_range):
    """
    Escanea la red en busca de dispositivos activos.
    :param ip_range: Rango de IPs a escanear (ej. "192.168.1.0/24").
    :return: Lista de dispositivos encontrados con sus IPs y MACs.
    """
    try:
        # Crear una solicitud ARP
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        # Enviar el paquete y recibir la respuesta
        result = srp(packet, timeout=2, verbose=0)[0]

        # Procesar la respuesta
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
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
            result_text += f"IP: {device['ip']}, MAC: {device['mac']}\n"
        
        # Mostrar el resultado con la opción de descargar
        mostrar_resultado_con_descarga(
            titulo="Detección de Máquinas",
            mensaje=result_text,
            nombre_archivo="escaneored.txt"
        )
    else:
        messagebox.showinfo("Detección de Máquinas", "No se encontraron dispositivos.")
# Configuración de la ventana principal
root = tk.Tk()
root.title("NetSecTools - Pentesting")
root.geometry("500x500")
root.configure(bg="#1e1e1e")

# Estilos personalizados
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Helvetica", 12), padding=10, background="#4CAF50", foreground="white", borderwidth=0)
style.map("TButton", background=[("active", "#45a049")])
style.configure("Accent.TButton", background="#FF5722", foreground="white")
style.map("Accent.TButton", background=[("active", "#E64A19")])

# Encabezado
header_label = tk.Label(root, text="NetSecTools", font=("Helvetica", 24, "bold"), bg="#1e1e1e", fg="#4CAF50")
header_label.pack(pady=20)

# Frame para los botones
button_frame = tk.Frame(root, bg="#1e1e1e")
button_frame.pack(pady=10)

# Botones
buttons = [
    ("Escaneo de Puertos", lambda: messagebox.showinfo("Escaneo de Puertos", "Función no implementada.")),
    ("Sniffer de Red", lambda: messagebox.showinfo("Sniffer de Red", "Función no implementada.")),
    ("Shell Inversa", lambda: messagebox.showinfo("Shell Inversa", "Función no implementada.")),
    ("Detección de Máquinas", open_network_scan),
    ("Ataque DDoS", lambda: messagebox.showinfo("Ataque DDoS", "Función no implementada.")),
    ("Fuerza Bruta", lambda: messagebox.showinfo("Fuerza Bruta", "Función no implementada.")),
    ("Man in the Middle", lambda: messagebox.showinfo("Man in the Middle", "Función no implementada.")),
    ("Keylogger", lambda: messagebox.showinfo("Keylogger", "Función no implementada.")),
]

# Organización de los botones en filas de 2
for i in range(0, len(buttons), 2):
    row_frame = tk.Frame(button_frame, bg="#1e1e1e")
    row_frame.pack(fill=tk.X, padx=20, pady=5)
    for j in range(2):
        if i + j < len(buttons):
            text, command = buttons[i + j]
            btn = ttk.Button(row_frame, text=text, command=command, style="TButton")
            btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)

root.mainloop()