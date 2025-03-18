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

from gui import start_gui

if __name__ == "__main__":
    start_gui()