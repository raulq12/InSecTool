import tkinter as tk
from tkinter import ttk, messagebox
import socket

# Función para escanear puertos
def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Tiempo de espera para la conexión
            result = sock.connect_ex((ip, port))
            if result == 0:  # Si el puerto está abierto
                open_ports.append(port)
            sock.close()
        except Exception as e:
            print(f"Error escaneando puerto {port}: {e}")
    return open_ports

def toggle_ip_input(command):
    for widget in target_frame.winfo_children():
        widget.destroy()
    
    if command:
        target_label = tk.Label(target_frame, text="IP Objetivo:", font=("Helvetica", 12), bg="#1e1e1e", fg="#ffffff")
        target_label.pack(pady=(10, 5))
        
        ip_entry = tk.Entry(target_frame, font=("Helvetica", 12), width=25, bg="#2d2d2d", fg="#ffffff", bd=0, insertbackground="white")
        ip_entry.pack(pady=5, ipady=5, fill=tk.X, padx=20)
        
        start_button = ttk.Button(target_frame, text="Iniciar", command=lambda: command(ip_entry.get()), style="Accent.TButton")
        start_button.pack(pady=10, ipady=5, fill=tk.X, padx=20)
        
        target_frame.pack(pady=10, fill=tk.X)
    else:
        target_frame.pack_forget()

def open_port_scanner(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    
    # Escanear puertos
    start_port = 1
    end_port = 12  # Rango de puertos a escanear
    open_ports = scan_ports(ip, start_port, end_port)
    
    if open_ports:
        messagebox.showinfo("Escaneo de Puertos", f"Puertos abiertos en {ip}:\n{', '.join(map(str, open_ports))}")
    else:
        messagebox.showinfo("Escaneo de Puertos", f"No se encontraron puertos abiertos en {ip}.")

def open_sniffer():
    toggle_ip_input(None)
    messagebox.showinfo("Sniffer de Red", "Herramienta de sniffer de red seleccionada.")

def open_reverse_shell(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return

    else:
        from socket import socket
        messagebox.showinfo("Shell Inversa", f"Conectando a {ip}...")


        # Definimos la dirección y puerto del servidor (Siempre de la máquina víctima)
        server_address = (ip)

        # Creamos el socket cliente, ya que restablecemos la conexión a cada comando que se ejecute
        client_socket = socket()
        client_socket.connect(server_address)
        estado = True

        while estado:

            # Solicitamos al usuario que introduzca un comando
            comando_enviar = input("Introduce el comando que quieras enviar a la máquina víctima (o 'exit' para salir): ")
            

            # Si el usuario introduce "exit", cerramos la conexión y salimos del bucle
            if comando_enviar == 'exit':
                # Le decimos al servidor que la conexion la cerramos:
                client_socket.send(comando_enviar.encode())
                # Cerramos el socket, que se volverá a abrir al inicio del bucle:
                client_socket.close()
                estado = False
            else:
                # Enviamos el comando a la máquina víctima:
                client_socket.send(comando_enviar.encode())

                # Esperamos a recibir la respuesta de la víctima y lo guardamos en la variable respuesta.
                respuesta = client_socket.recv(4096)

                # Imprimimos la respuesta;
                print(respuesta.decode()) 


def open_network_scan(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Detección de Máquinas", f"Escaneando red en {ip}...")

def open_ddos_attack(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Ataque DDoS", f"Iniciando ataque DDoS contra {ip}...")

def open_brute_force(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Fuerza Bruta", f"Iniciando ataque de fuerza bruta en {ip}...")

def open_mitm(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Man in the Middle", f"Iniciando ataque MITM en {ip}...")

def open_keylogger():
    toggle_ip_input(None)
    messagebox.showinfo("Keylogger", "Herramienta de keylogger seleccionada.")

def reverse_shell_command():
    toggle_ip_input(open_reverse_shell)

def port_scanner_command():
    toggle_ip_input(open_port_scanner)

def network_scan_command():
    toggle_ip_input(open_network_scan)

def ddos_attack_command():
    toggle_ip_input(open_ddos_attack)

def brute_force_command():
    toggle_ip_input(open_brute_force)

def mitm_command():
    toggle_ip_input(open_mitm)

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

# Frame para la entrada de IP
target_frame = tk.Frame(root, bg="#1e1e1e")
target_frame.pack_forget()

# Frame para los botones
button_frame = tk.Frame(root, bg="#1e1e1e")
button_frame.pack(pady=10)

# Botones
buttons = [
    ("Escaneo de Puertos", port_scanner_command),
    ("Sniffer de Red", open_sniffer),
    ("Shell Inversa", reverse_shell_command),
    ("Detección de Máquinas", network_scan_command),
    ("Ataque DDoS", ddos_attack_command),
    ("Fuerza Bruta", brute_force_command),
    ("Man in the Middle", mitm_command),
    ("Keylogger", open_keylogger),
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