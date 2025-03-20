import subprocess
import sys

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

def is_package_installed(package_name):
    """Verifica si un paquete del sistema está instalado"""
    try:
        subprocess.run(
            f"dpkg -l {package_name}",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError:
        return False

def install_system_dependencies():
    """Instala dependencias del sistema (nmap) si no están instaladas"""
    packages = ["nmap"]
    needs_update = False

    # Verificar si falta algún paquete
    for package in packages:
        if not is_package_installed(package):
            print_info(f"{package} no está instalado. Se instalará.")
            needs_update = True

    # Actualizar e instalar solo si es necesario
    if needs_update:
        print_info("Actualizando lista de paquetes...")
        if not run_command(
            "sudo apt update",
            "Fallo al actualizar la lista de paquetes"
        ):
            sys.exit(1)

        for package in packages:
            if not is_package_installed(package):
                print_info(f"Instalando {package}...")
                if not run_command(
                    f"sudo apt install -y {package}",
                    f"Fallo al instalar {package}"
                ):
                    sys.exit(1)
    else:
        print_info("Todos los paquetes del sistema están instalados.")

def is_python_package_installed(package_name):
    """Verifica si un paquete de Python está instalado"""
    try:
        subprocess.run(
            f"python3 -m pip show {package_name}",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError:
        return False

def install_python_packages():
    """Instala paquetes de Python globalmente si no están instalados"""
    packages = ["python-nmap", "scapy", "keyboard"]
    needs_install = False

    # Verificar si falta algún paquete de Python
    for package in packages:
        if not is_python_package_installed(package):
            print_info(f"{package} no está instalado. Se instalará.")
            needs_install = True

    # Instalar solo si es necesario
    if needs_install:
        print_info("Instalando paquetes de Python...")
        if not run_command(
            "python3 -m pip install --break-system-packages " + " ".join(packages),
            "Fallo al instalar paquetes de Python"
        ):
            sys.exit(1)
    else:
        print_info("Todos los paquetes de Python están instalados.")

def main():
    try:
        # Instalar dependencias del sistema (si es necesario)
        install_system_dependencies()

        # Instalar paquetes de Python (si es necesario)
        install_python_packages()

        print_success("¡Todas las dependencias están instaladas correctamente!")

    except Exception as e:
        print_error(f"Error crítico: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()