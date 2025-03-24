import tkinter as tk
from tkinter import ttk, messagebox

# Importamos las funciones de manera condicional para manejar posibles errores
def import_functions():
    try:
        from functions import open_reverse_shell, open_port_scanner, open_network_scan, keylogger
        from utils import mostrar_resultado_con_descarga
        return open_reverse_shell, open_port_scanner, open_network_scan, keylogger, mostrar_resultado_con_descarga
    except ImportError as e:
        print(f"Error al importar funciones: {e}")
        print("Asegúrate de que los archivos functions.py y utils.py existan y sean accesibles.")
        return None, None, None, None, None

def start_gui():
    # Importar funciones necesarias
    open_reverse_shell, open_port_scanner, open_network_scan, keylogger, mostrar_resultado_con_descarga = import_functions()
    if open_reverse_shell is None:
        print("No se pueden cargar las funciones necesarias. Saliendo...")
        return
    
    # Configuración de la ventana principal
    root = tk.Tk()
    root.title("NetSecTools - Pentesting")
    root.geometry("500x600")  # Aumentamos el tamaño para acomodar los nuevos elementos
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

    # Frame para los campos de entrada de la shell inversa
    reverse_shell_frame = tk.Frame(root, bg="#1e1e1e")
    reverse_shell_frame.pack(pady=10)

    # Función para mostrar los campos de entrada de la shell inversa
    def show_reverse_shell_inputs():
        # Limpiar el frame antes de agregar nuevos elementos
        for widget in reverse_shell_frame.winfo_children():
            widget.destroy()

        # Campo de entrada para la IP
        tk.Label(reverse_shell_frame, text="IP Víctima:", bg="#1e1e1e", fg="white").pack(pady=5)
        ip_entry = tk.Entry(reverse_shell_frame, width=30)
        ip_entry.pack(pady=5)

        # Botón para iniciar la shell inversa
        def start_reverse_shell():
            ip = ip_entry.get()
            if not ip:
                messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
                return
            open_reverse_shell(ip)

        tk.Button(reverse_shell_frame, text="Iniciar Shell Inversa", command=start_reverse_shell, bg="#FF5722", fg="white").pack(pady=10)

    # Función para mostrar los campos de entrada del escaneo de puertos
    def show_port_scan_inputs():
        # Limpiar el frame antes de agregar nuevos elementos
        for widget in reverse_shell_frame.winfo_children():
            widget.destroy()

        # Campos de entrada
        tk.Label(reverse_shell_frame, text="IP Víctima:", bg="#1e1e1e", fg="white").pack(pady=5)
        ip_entry = tk.Entry(reverse_shell_frame, width=30)
        ip_entry.pack(pady=5)

        tk.Label(reverse_shell_frame, text="Puerto de Inicio:", bg="#1e1e1e", fg="white").pack(pady=5)
        start_port_entry = tk.Entry(reverse_shell_frame, width=30)
        start_port_entry.pack(pady=5)

        tk.Label(reverse_shell_frame, text="Puerto de Fin:", bg="#1e1e1e", fg="white").pack(pady=5)
        end_port_entry = tk.Entry(reverse_shell_frame, width=30)
        end_port_entry.pack(pady=5)

        # Botón de escanear
        def start_scan():
            ip = ip_entry.get()
            start_port = start_port_entry.get()
            end_port = end_port_entry.get()

            # Validar los campos
            if not ip or not start_port or not end_port:
                messagebox.showerror("Error", "Por favor, completa todos los campos.")
                return

            try:
                start_port = int(start_port)
                end_port = int(end_port)
            except ValueError:
                messagebox.showerror("Error", "Los puertos deben ser números enteros.")
                return

            # Llamar a la función de escaneo de puertos
            open_port_scanner(ip, start_port, end_port)

        tk.Button(reverse_shell_frame, text="Escanear", command=start_scan, bg="#4CAF50", fg="white").pack(pady=10)

    # Botones
    buttons = [
        ("Escaneo de Puertos", show_port_scan_inputs),
        ("Sniffer de Red", lambda: messagebox.showinfo("Sniffer de Red", "Función no implementada.")),
        ("Shell Inversa", show_reverse_shell_inputs),
        ("Detección de Máquinas", open_network_scan),
        ("Ataque DDoS", lambda: messagebox.showinfo("Ataque DDoS", "Función no implementada.")),
        ("Fuerza Bruta", lambda: messagebox.showinfo("Fuerza Bruta", "Función no implementada.")),
        ("Man in the Middle", lambda: messagebox.showinfo("Man in the Middle", "Función no implementada.")),
        ("Keylogger", keylogger),
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
