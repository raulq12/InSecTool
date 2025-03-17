import subprocess
import sys
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
import nmap

# Ruta del entorno virtual
VENV_DIR = "venv"
ACTIVATE_SCRIPT = os.path.join(VENV_DIR, "bin", "activate")  # Linux/macOS
if sys.platform == "win32":
    ACTIVATE_SCRIPT = os.path.join(VENV_DIR, "Scripts", "activate")  # Windows

def activate_venv():
    """Activa el entorno virtual."""
    try:
        if sys.platform == "win32":
            # En Windows, usamos el comando `call` para ejecutar el script de activación
            subprocess.run(f"call {ACTIVATE_SCRIPT}", shell=True, check=True)
        else:
            # En Linux/macOS, usamos `source`
            subprocess.run(f"source {ACTIVATE_SCRIPT}", shell=True, check=True)
        print("Entorno virtual activado.")
    except subprocess.CalledProcessError as e:
        print(f"Error al activar el entorno virtual: {e}")
        sys.exit(1)

def deactivate_venv():
    """Desactiva el entorno virtual."""
    try:
        if sys.platform == "win32":
            # En Windows, no hay un comando directo para desactivar, pero salir del entorno virtual es suficiente
            print("Entorno virtual desactivado (Windows).")
        else:
            # En Linux/macOS, usamos `deactivate`
            subprocess.run("deactivate", shell=True, check=True)
            print("Entorno virtual desactivado.")
    except subprocess.CalledProcessError as e:
        print(f"Error al desactivar el entorno virtual: {e}")

def scan_ports():
    """Realiza el escaneo de puertos."""
    target = entry_target.get()
    port_range = entry_port_range.get()

    if not target or not port_range:
        messagebox.showerror("Error", "Por favor, ingresa un objetivo y un rango de puertos.")
        return

    try:
        nm = nmap.PortScanner()
        nm.scan(target, port_range)

        result_text.delete(1.0, tk.END)  # Limpiar el área de texto
        for host in nm.all_hosts():
            result_text.insert(tk.END, f"Host: {host} ({nm[host].hostname()})\n")
            result_text.insert(tk.END, f"Estado: {nm[host].state()}\n")
            for proto in nm[host].all_protocols():
                result_text.insert(tk.END, f"Protocolo: {proto}\n")
                ports = nm[host][proto].keys()
                for port in ports:
                    result_text.insert(tk.END, f"Puerto: {port}\tEstado: {nm[host][proto][port]['state']}\n")
    except Exception as e:
        messagebox.showerror("Error", f"Ocurrió un error durante el escaneo: {e}")

def main():
    """Función principal para ejecutar la interfaz gráfica."""
    # Activar el entorno virtual
    activate_venv()

    # Crear la ventana principal
    root = tk.Tk()
    root.title("Escaneo de Puertos con Nmap")

    # Crear y colocar los widgets en la ventana
    label_target = tk.Label(root, text="Objetivo (IP o dominio):")
    label_target.grid(row=0, column=0, padx=10, pady=10)

    entry_target = tk.Entry(root, width=30)
    entry_target.grid(row=0, column=1, padx=10, pady=10)

    label_port_range = tk.Label(root, text="Rango de puertos (e.g., 1-1000):")
    label_port_range.grid(row=1, column=0, padx=10, pady=10)

    entry_port_range = tk.Entry(root, width=30)
    entry_port_range.grid(row=1, column=1, padx=10, pady=10)

    button_scan = tk.Button(root, text="Escanear", command=scan_ports)
    button_scan.grid(row=2, column=0, columnspan=2, pady=10)

    result_text = scrolledtext.ScrolledText(root, width=60, height=20)
    result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    # Iniciar el bucle principal de la interfaz gráfica
    root.mainloop()

    # Desactivar el entorno virtual al salir
    deactivate_venv()

if __name__ == "__main__":
    main()