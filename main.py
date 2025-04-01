import os
import sys
import subprocess
from tkinter import messagebox
def enforce_root():
    """Fuerza la ejecución como superusuario"""
    if os.geteuid() != 0:
        print("ERROR: Debes ejecutar como superusuario")
        print("Ejemplo: sudo python3 main.py")
        sys.exit(1)

def check_root():
    if os.geteuid() != 0:
        print("Ejecuta como superusuario: sudo python3 main.py")
        sys.exit(1)


def check_dependencies():
    try:
        __import__('nmap')
        __import__('scapy')
        __import__('keyboard')
        __import__('netifaces')
        __import__('paramiko')
        return True
    except ImportError:
        return False

def auto_install():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    installer = os.path.join(script_dir, 'install.sh')
    
    if os.path.exists(installer):
        os.chmod(installer, 0o755)
        subprocess.run(['sudo', installer], check=True)
    else:
        messagebox.showerror("Error", "Instalador automático no encontrado")
        sys.exit(1)

if not check_dependencies():
    auto_install()

if not check_dependencies():
    messagebox.showerror("Error", "No se pudieron instalar todas las dependencias")
    sys.exit(1)

try:
    from gui import start_gui
    start_gui()
except Exception as e:
    messagebox.showerror("Error", f"Error al iniciar la aplicación: {str(e)}")


if __name__ == "__main__":
    enforce_root()  # Verificación de root

    # Verificar e instalar dependencias
    if not check_dependencies():
        auto_install()

    # Iniciar aplicación
    try:
        from gui import start_gui
        start_gui()
    except Exception as e:
        messagebox.showerror("Error", f"Error crítico: {str(e)}")
        sys.exit(1)
