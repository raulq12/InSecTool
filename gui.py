import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from functions import (
    open_port_scanner,
    open_reverse_shell,
    open_network_scan,
    open_ddos_attack,
    open_brute_force,
    open_mitm_attack,
    open_sniffer,
    keylogger
)
import threading
import os

class NetSecToolsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSecTools")
        self.root.geometry("700x600")
        self.root.configure(bg="#f0f0f0")
        
        self.setup_ui()
    
    def setup_ui(self):
        # Frame principal
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(pady=20, padx=20, fill=tk.BOTH, expand=True)
        
        # Título
        title = tk.Label(
            main_frame,
            text="NetSecTools - Pentesting Toolkit",
            font=("Helvetica", 16, "bold"),
            bg="#f0f0f0"
        )
        title.pack(pady=10)
        
        # Frame de botones
        button_frame = tk.Frame(main_frame, bg="#f0f0f0")
        button_frame.pack(fill=tk.BOTH, expand=True)
        
        # Botones de escaneo
        scan_frame = tk.LabelFrame(button_frame, text="Escaneo", bg="#f0f0f0")
        scan_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        
        ttk.Button(
            scan_frame,
            text="Escaneo de Puertos",
            command=self.show_port_scanner
        ).pack(pady=5, fill=tk.X)
        
        ttk.Button(
            scan_frame,
            text="Escaneo de Red",
            command=open_network_scan
        ).pack(pady=5, fill=tk.X)
        
        ttk.Button(
            scan_frame,
            text="Sniffer de Paquetes",
            command=self.show_sniffer
        ).pack(pady=5, fill=tk.X)
        
        # Botones de ataques
        attack_frame = tk.LabelFrame(button_frame, text="Ataques", bg="#f0f0f0")
        attack_frame.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")
        
        ttk.Button(
            attack_frame,
            text="Shell Inversa",
            command=self.show_reverse_shell
        ).pack(pady=5, fill=tk.X)
        
        ttk.Button(
            attack_frame,
            text="Ataque DDoS",
            command=self.show_ddos
        ).pack(pady=5, fill=tk.X)
        
        ttk.Button(
            attack_frame,
            text="Fuerza Bruta SSH",
            command=self.show_brute_force
        ).pack(pady=5, fill=tk.X)
        
        ttk.Button(
            attack_frame,
            text="Man in the Middle",
            command=self.show_mitm
        ).pack(pady=5, fill=tk.X)
        
        # Botones de monitorización
        monitor_frame = tk.LabelFrame(button_frame, text="Monitorización", bg="#f0f0f0")
        monitor_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        ttk.Button(
            monitor_frame,
            text="Keylogger",
            command=keylogger
        ).pack(pady=5, fill=tk.X)
        
        # Configurar grid
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_rowconfigure(0, weight=1)
        button_frame.grid_rowconfigure(1, weight=1)
    
    # Funciones para mostrar las ventanas de cada herramienta
    def show_port_scanner(self):
        self.show_input_window(
            "Escaneo de Puertos",
            ["IP Objetivo:", "Puerto Inicial:", "Puerto Final:"],
            lambda ip, start, end: open_port_scanner(ip, start, end)
        )
    
    def show_reverse_shell(self):
        self.show_input_window(
            "Shell Inversa",
            ["IP Objetivo:"],
            lambda ip: open_reverse_shell(ip)
        )
    
    def show_ddos(self):
        self.show_input_window(
            "Ataque DDoS",
            ["IP Objetivo:", "Puerto:", "Duración (segundos):"],
            lambda ip, port, dur: open_ddos_attack(ip, port, dur)
        )
    
    def show_brute_force(self):
        window = tk.Toplevel(self.root)
        window.title("Fuerza Bruta SSH")
        
        tk.Label(window, text="IP Objetivo:").grid(row=0, column=0, padx=5, pady=5)
        ip_entry = tk.Entry(window)
        ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(window, text="Usuario:").grid(row=1, column=0, padx=5, pady=5)
        user_entry = tk.Entry(window)
        user_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(window, text="Diccionario:").grid(row=2, column=0, padx=5, pady=5)
        
        file_frame = tk.Frame(window)
        file_frame.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        
        path_entry = tk.Entry(file_frame)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        tk.Button(
            file_frame,
            text="...",
            command=lambda: self.browse_file(path_entry)
        ).pack(side=tk.RIGHT)
        
        tk.Button(
            window,
            text="Iniciar Ataque",
            command=lambda: open_brute_force(
                ip_entry.get(),
                user_entry.get(),
                path_entry.get()
            )
        ).grid(row=3, column=0, columnspan=2, pady=10)
    
    def show_mitm(self):
        window = tk.Toplevel(self.root)
        window.title("MITM Attack")
        
        # Variables de control
        self.mitm_thread = None
        
        # Interfaz
        tk.Label(window, text="IP Víctima:").grid(row=0, column=0, padx=5, pady=5)
        target_entry = tk.Entry(window)
        target_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(window, text="IP Gateway:").grid(row=1, column=0, padx=5, pady=5)
        gateway_entry = tk.Entry(window)
        gateway_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(window, text="Interfaz:").grid(row=2, column=0, padx=5, pady=5)
        iface_entry = tk.Entry(window)
        iface_entry.insert(0, "eth0")
        iface_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Botón de control
        self.mitm_btn = ttk.Button(
            window,
            text="Iniciar MITM",
            command=self.toggle_mitm
        )
        self.mitm_btn.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Guardar referencias
        self.mitm_target_entry = target_entry
        self.mitm_gateway_entry = gateway_entry
        self.mitm_iface_entry = iface_entry

    def toggle_mitm(self):
        """Alternar entre inicio y detención del MITM"""
        if self.mitm_thread and self.mitm_thread.is_alive():
            # Detener el ataque
            self.mitm_thread.running = False
            self.mitm_thread.join()
            self.mitm_btn.config(text="Iniciar MITM")
            messagebox.showinfo("MITM", "Ataque detenido")
        else:
            # Iniciar nuevo ataque
            target = self.mitm_target_entry.get()
            gateway = self.mitm_gateway_entry.get()
            iface = self.mitm_iface_entry.get()
            
            if target and gateway:
                self.mitm_thread = mitm_arp_spoof(target, gateway, iface)
                if self.mitm_thread:
                    self.mitm_btn.config(text="Detener MITM")
        def stop_attack():
            if self.mitm_active and self.mitm_thread:
                self.mitm_active = False
                # Aquí necesitarías una forma de detener el hilo MITM
                btn.config(text="Iniciar MITM", bg="SystemButtonFace")
        
        btn = tk.Button(
            window,
            text="Iniciar MITM",
            command=lambda: start_attack() if not self.mitm_active else stop_attack()
        )
        btn.grid(row=3, column=0, columnspan=2)
    
    def show_sniffer(self):
        self.show_input_window(
            "Sniffer de Paquetes",
            ["Interfaz (ej. eth0):", "Tiempo (segundos):"],
            lambda iface, timeout: open_sniffer(iface, timeout)
        )
    
    # Funciones auxiliares
    def show_input_window(self, title, fields, callback):
        window = tk.Toplevel(self.root)
        window.title(title)
        
        entries = []
        for i, field in enumerate(fields):
            tk.Label(window, text=field).grid(row=i, column=0, padx=5, pady=5)
            entry = tk.Entry(window)
            entry.grid(row=i, column=1, padx=5, pady=5)
            entries.append(entry)
        
        tk.Button(
            window,
            text="Ejecutar",
            command=lambda: self.execute_callback(callback, entries)
        ).grid(row=len(fields), column=0, columnspan=2, pady=10)
    
    def execute_callback(self, callback, entries):
        args = [entry.get() for entry in entries]
        threading.Thread(target=callback, args=args, daemon=True).start()
    
    def browse_file(self, entry_widget):
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

def start_gui():
    root = tk.Tk()
    app = NetSecToolsGUI(root)
    root.mainloop()