import os
import sys
import subprocess
import platform
from tkinter import messagebox

def enforce_root():
    """Fuerza ejecución como superusuario"""
    if os.geteuid() != 0:
        if platform.system() != "Linux":
            messagebox.showerror("Error", "Esta herramienta solo funciona en Linux")
            sys.exit(1)
            
        print("\n[!] Se requieren privilegios de superusuario")
        print("[*] Reiniciando con sudo...")
        try:
            subprocess.call(['sudo', sys.executable] + sys.argv)
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error: {e}")
            sys.exit(1)

def check_dependencies():
    """Verifica dependencias"""
    required = ['nmap', 'scapy', 'keyboard', 'netifaces', 'paramiko']
    missing = []
    
    for module in required:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print("\n[!] Faltan dependencias:")
        for m in missing:
            print(f"  - {m}")
        print("\nInstala con: sudo apt install python3-{nmap,scapy,keyboard,netifaces,paramiko}")
    
    return not missing

def main():
    """Función principal"""
    enforce_root()
    
    if not check_dependencies():
        messagebox.showerror("Error", "Instala las dependencias faltantes")
        sys.exit(1)
    
    try:
        from gui import setup_gui
        setup_gui()
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo iniciar: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()