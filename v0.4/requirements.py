import subprocess
import sys
import platform
import os

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

    @staticmethod
    def use_colors():
        # En Windows, los colores ANSI solo funcionan en terminales modernas o con módulos especiales
        return platform.system() != "Windows" or "ANSICON" in os.environ

def print_error(message):
    if Colors.use_colors():
        print(f"{Colors.RED}Error: {message}{Colors.RESET}", file=sys.stderr)
    else:
        print(f"Error: {message}", file=sys.stderr)

def print_success(message):
    if Colors.use_colors():
        print(f"{Colors.GREEN}Éxito: {message}{Colors.RESET}")
    else:
        print(f"Éxito: {message}")

def print_info(message):
    if Colors.use_colors():
        print(f"{Colors.BLUE}Info: {message}{Colors.RESET}")
    else:
        print(f"Info: {message}")

def run_command(command, error_message):
    try:
        subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"{error_message}: {e}")
        return False

def is_windows():
    return platform.system() == "Windows"

def is_package_installed(package_name):
    """Verifica si un paquete del sistema está instalado"""
    if is_windows():
        # En Windows no usamos dpkg, así que asumimos que no está instalado
        # y lo manejaremos de otra manera
        return False
    else:
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

def is_nmap_installed():
    """Verifica si nmap está instalado en cualquier sistema operativo"""
    try:
        subprocess.run(
            "nmap --version",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_system_dependencies():
    """Instala dependencias del sistema según el sistema operativo"""
    if is_windows():
        # En Windows, verificamos nmap
        if not is_nmap_installed():
            print_info("Nmap no está instalado en Windows.")
            print_info("Por favor, descarga e instala Nmap desde: https://nmap.org/download.html")
            print_info("Después de instalarlo, asegúrate de que esté en el PATH del sistema.")
            response = input("¿Deseas continuar con la instalación de los paquetes de Python? (s/n): ")
            if response.lower() != 's':
                sys.exit(1)
        else:
            print_info("Nmap está instalado en Windows.")
    else:
        # En Linux/Unix
        packages = ["nmap", "python3-pip"]
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

def is_pip_available():
    """Verifica si pip está disponible para Python 3"""
    try:
        python_cmd = "python" if is_windows() else "python3"
        subprocess.run(
            f"{python_cmd} -m pip --version",
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except subprocess.CalledProcessError:
        return False

def is_python_package_installed(package_name):
    """Verifica si un paquete de Python está instalado"""
    try:
        python_cmd = "python" if is_windows() else "python3"
        subprocess.run(
            f"{python_cmd} -m pip show {package_name}",
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
    python_cmd = "python" if is_windows() else "python3"
    
    # Primero verificar si pip está disponible
    if not is_pip_available():
        if is_windows():
            print_info("pip no está disponible. Instalando pip...")
            # En Windows, descargamos get-pip.py
            if not run_command(
                "curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && " + 
                f"{python_cmd} get-pip.py",
                "Fallo al instalar pip"
            ):
                sys.exit(1)
        else:
            print_info("pip no está disponible. Instalando python3-pip...")
            if not run_command(
                "sudo apt update && sudo apt install -y python3-pip",
                "Fallo al instalar python3-pip"
            ):
                sys.exit(1)
    
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
        try:
            # Comando básico de instalación
            cmd = f"{python_cmd} -m pip install " + " ".join(packages)
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError:
            # Manejo específico según el sistema operativo
            if is_windows():
                # En Windows, intentar con privilegios elevados
                print_info("Reintentando con privilegios elevados...")
                print_info("Es posible que se abra un diálogo de control de cuentas de usuario.")
                # Usamos comillas simples para la cadena completa y escapamos las comillas internas
                if not run_command(
                    f'powershell -Command "Start-Process \"{python_cmd}\" -ArgumentList \"-m pip install {" ".join(packages)}\" -Verb RunAs"',
                    "Fallo al instalar paquetes de Python"
                ):
                    sys.exit(1)
            else:
                # En Linux, intentar con --break-system-packages
                print_info("Reintentando con --break-system-packages...")
                if not run_command(
                    f"{python_cmd} -m pip install --break-system-packages " + " ".join(packages),
                    "Fallo al instalar paquetes de Python"
                ):
                    sys.exit(1)
    else:
        print_info("Todos los paquetes de Python están instalados.")

def main():
    try:
        print_info(f"Sistema operativo detectado: {platform.system()}")
        
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
