import subprocess
import sys
import os

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

def print_message(color, message):
    print(f"{color}{message}{Colors.RESET}")

def run_command(command):
    """Ejecuta un comando en la terminal y verifica si se ejecutó correctamente."""
    try:
        subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def is_superuser():
    """Verifica si el script se está ejecutando con privilegios de superusuario."""
    return os.geteuid() == 0

def restart_as_superuser():
    """Reinicia el script con privilegios de superusuario si no los tiene."""
    if not is_superuser():
        print_message(Colors.BLUE, "No eres superusuario. Reiniciando con privilegios de administrador...")
        subprocess.call(["sudo", "python3"] + sys.argv)
        sys.exit()

def is_package_installed(package_name):
    """Verifica si un paquete del sistema está instalado."""
    return run_command(f"dpkg -l {package_name}")

def install_system_packages():
    """Verifica e instala paquetes del sistema operativo si son necesarios."""
    packages = ["nmap", "python3-pip"]
    missing_packages = [pkg for pkg in packages if not is_package_installed(pkg)]

    if missing_packages:
        print_message(Colors.BLUE, "Actualizando lista de paquetes...")
        if not run_command("sudo apt update"):
            print_message(Colors.RED, "Error al actualizar la lista de paquetes.")
            sys.exit(1)

        for package in missing_packages:
            print_message(Colors.BLUE, f"Instalando {package}...")
            if not run_command(f"sudo apt install -y {package}"):
                print_message(Colors.RED, f"Error al instalar {package}.")
                sys.exit(1)
    else:
        print_message(Colors.GREEN, "Todos los paquetes del sistema están instalados.")

def is_python_package_installed(package_name):
    """Verifica si un paquete de Python está instalado."""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False

def install_python_packages():
    """Verifica e instala paquetes de Python si son necesarios."""
    packages = ["python-nmap", "scapy", "keyboard", "netifaces"]
    missing_packages = [pkg for pkg in packages if not is_python_package_installed(pkg)]

    if missing_packages:
        print_message(Colors.BLUE, "Instalando paquetes de Python...")
        for package in missing_packages:
            if not run_command(f"python3 -m pip install {package}"):
                print_message(Colors.RED, f"Error al instalar {package}.")
                sys.exit(1)
    else:
        print_message(Colors.GREEN, "Todos los paquetes de Python están instalados.")

def main():
    """Función principal para verificar e instalar dependencias."""
    restart_as_superuser()
    print_message(Colors.BLUE, "Verificando e instalando dependencias...")
    install_system_packages()
    install_python_packages()
    print_message(Colors.GREEN, "¡Todas las dependencias están instaladas correctamente!")

if __name__ == "__main__":
    main()
