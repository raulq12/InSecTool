import subprocess
import sys
import os
import urllib.request

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

def print_error(message):
    print(f"{Colors.RED}Error: {message}{Colors.RESET}", file=sys.stderr)

def print_success(message):
    print(f"{Colors.GREEN}Éxito: {message}{Colors.RESET}")

def print_info(message):
    print(f"{Colors.BLUE}Info: {message}{Colors.RESET}")

def run_command(command, error_message):
    try:
        subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"{error_message}: {e}")
        return False

def install_system_dependencies():
    """Instala dependencias del sistema necesarias (nmap y python3-venv)"""
    print_info("Instalando dependencias del sistema (nmap y python3-venv)...")
    if not run_command(
        "sudo apt update && sudo apt install -y nmap python3-venv curl",
        "Fallo al instalar dependencias del sistema"
    ):
        sys.exit(1)

def create_clean_venv():
    """Crea un entorno virtual limpio"""
    venv_dir = "venv"
    if os.path.exists(venv_dir):
        print_info("Eliminando entorno virtual existente...")
        if not run_command(f"rm -rf {venv_dir}", "Fallo al eliminar entorno virtual"):
            sys.exit(1)
    
    print_info("Creando nuevo entorno virtual...")
    if not run_command(f"{sys.executable} -m venv {venv_dir}", "Fallo al crear entorno virtual"):
        sys.exit(1)

def install_pip_in_venv():
    """Instala pip manualmente en el entorno virtual"""
    print_info("Instalando pip en el entorno virtual...")
    venv_python = os.path.join("venv", "bin", "python3")
    
    try:
        # Descargar get-pip.py
        urllib.request.urlretrieve(
            "https://bootstrap.pypa.io/get-pip.py",
            "get-pip.py"
        )
        
        # Instalar pip
        if not run_command(
            f"{venv_python} get-pip.py",
            "Fallo al instalar pip"
        ):
            sys.exit(1)
        
        # Limpiar archivo temporal
        os.remove("get-pip.py")
    except Exception as e:
        print_error(f"Fallo al descargar/instalar pip: {e}")
        sys.exit(1)

def install_python_nmap():
    """Instala python-nmap en el entorno virtual"""
    print_info("Instalando python-nmap...")
    venv_pip = os.path.join("venv", "bin", "pip3")
    if not run_command(
        f"{venv_pip} install python-nmap",
        "Fallo al instalar python-nmap"
    ):
        sys.exit(1)

def main():
    try:
        # Paso 1: Instalar dependencias del sistema (nmap y python3-venv)
        install_system_dependencies()
        
        # Paso 2: Crear entorno virtual limpio
        create_clean_venv()
        
        # Paso 3: Instalar pip manualmente en el entorno virtual
        install_pip_in_venv()
        
        # Paso 4: Instalar python-nmap en el entorno virtual
        install_python_nmap()
        
        print_success("Instalación completada con éxito!")
        print_info("Activa el entorno virtual con: source venv/bin/activate")

    except Exception as e:
        print_error(f"Error crítico: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
