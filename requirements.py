import subprocess
import sys
import os

# Colores para resaltar mensajes en la consola
class Colors:
    RED = "\033[91m"    # Rojo
    GREEN = "\033[92m"  # Verde
    YELLOW = "\033[93m" # Amarillo
    BLUE = "\033[94m"   # Azul
    RESET = "\033[0m"   # Restablecer color

def print_error(message):
    """Muestra un mensaje de error en rojo."""
    print(f"{Colors.RED}Error: {message}{Colors.RESET}", file=sys.stderr)

def print_warning(message):
    """Muestra un mensaje de advertencia en amarillo."""
    print(f"{Colors.YELLOW}Advertencia: {message}{Colors.RESET}", file=sys.stderr)

def print_success(message):
    """Muestra un mensaje de éxito en verde."""
    print(f"{Colors.GREEN}Éxito: {message}{Colors.RESET}")

def print_info(message):
    """Muestra un mensaje informativo en azul."""
    print(f"{Colors.BLUE}Info: {message}{Colors.RESET}")

def run_command(command, error_message):
    """Ejecuta un comando y muestra un mensaje de error si falla."""
    try:
        subprocess.run(command, check=True, shell=True)
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"{error_message}: {e}")
        return False

def install_pip():
    """Instala pip si no está instalado."""
    print_info("Verificando si pip está instalado...")
    if not run_command(f"{sys.executable} -m pip --version", "Verificación de pip falló"):
        print_info("Instalando pip...")
        if not run_command("sudo apt update && sudo apt install -y python3-pip", "No se pudo instalar pip"):
            sys.exit(1)

def install_python_venv():
    """Instala python3-venv si no está instalado."""
    print_info("Verificando si python3-venv está instalado...")
    if not run_command("dpkg -l python3-venv", "Verificación de python3-venv falló"):
        print_info("Instalando python3-venv...")
        if not run_command("sudo apt update && sudo apt install -y python3-venv", "No se pudo instalar python3-venv"):
            print_warning("Asegúrate de que no haya repositorios no válidos en tu sistema.")
            sys.exit(1)

def create_venv():
    """Crea un entorno virtual."""
    venv_dir = "venv"
    print_info("Creando entorno virtual...")
    if not os.path.exists(venv_dir):
        if not run_command(f"{sys.executable} -m venv {venv_dir}", "No se pudo crear el entorno virtual"):
            sys.exit(1)
    print_success(f"Entorno virtual creado en {venv_dir}.")

def install_nmap():
    """Instala nmap si no está instalado."""
    print_info("Verificando si nmap está instalado...")
    if not run_command("nmap --version", "Verificación de nmap falló"):
        print_info("Instalando nmap...")
        if not run_command("sudo apt update && sudo apt install -y nmap", "No se pudo instalar nmap"):
            print_warning("Asegúrate de que no haya repositorios no válidos en tu sistema.")
            sys.exit(1)

def ensure_pip_in_venv():
    """Asegura que pip esté instalado en el entorno virtual."""
    venv_python = os.path.join("venv", "bin", "python3")
    print_info("Verificando si pip está instalado en el entorno virtual...")
    if not run_command(f"{venv_python} -m pip --version", "Verificación de pip en el entorno virtual falló"):
        print_info("Instalando pip en el entorno virtual...")
        if not run_command(f"{venv_python} -m ensurepip --upgrade", "No se pudo instalar pip en el entorno virtual"):
            sys.exit(1)

def install_python_nmap():
    """Instala python-nmap dentro del entorno virtual."""
    venv_python = os.path.join("venv", "bin", "python3")
    print_info("Verificando si python-nmap está instalado...")
    if not run_command(f"{venv_python} -m pip show python-nmap", "Verificación de python-nmap falló"):
        print_info("Instalando python-nmap...")
        if not run_command(f"{venv_python} -m pip install python-nmap", "No se pudo instalar python-nmap"):
            sys.exit(1)

def install_dependencies():
    """Verifica e instala todas las dependencias necesarias."""
    print_info("Instalando dependencias...")
    
    # Instalar pip
    install_pip()

    # Instalar python3-venv
    install_python_venv()

    # Crear el entorno virtual
    create_venv()

    # Asegurar que pip esté instalado en el entorno virtual
    ensure_pip_in_venv()

    # Instalar nmap
    install_nmap()

    # Instalar python-nmap dentro del entorno virtual
    install_python_nmap()

    print_success("Todas las dependencias se instalaron correctamente.")
    print_info("Activa el entorno virtual con: source venv/bin/activate")

# Ejecutar la verificación e instalación de dependencias
if __name__ == "__main__":
    install_dependencies()