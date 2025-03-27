import sys
import subprocess
import platform
import os

def check_and_install_tkinter():
    try:
        import tkinter
        return True
    except ImportError:
        print("El m\u00f3dulo tkinter no est\u00e1 instalado. Intentando instalarlo...")
        try:
            system = platform.system().lower()
            
            if "linux" in system:
                subprocess.run(["sudo", "apt-get", "update"], check=True)
                subprocess.run(["sudo", "apt-get", "install", "-y", "python3-tk"], check=True)
            elif "darwin" in system:
                print("En macOS, tkinter deber\u00eda venir con Python. Intenta reinstalar Python.")
                return False
            elif "windows" in system:
                print("En Windows, tkinter deber\u00eda venir con Python.")
                return False
            else:
                print(f"Sistema operativo no reconocido: {system}")
                return False

            print("tkinter instalado correctamente. Reiniciando la aplicaci\u00f3n...")
            return True
        except subprocess.SubprocessError as e:
            print(f"Error al instalar tkinter: {e}")
            return False

def check_dependencies():
    try:
        modules_to_check = ["scapy", "nmap", "keyboard"]
        missing_modules = []

        for module in modules_to_check:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)

        if missing_modules:
            print(f"Faltan los siguientes m\u00f3dulos: {', '.join(missing_modules)}")
            pip_cmd = "pip" if platform.system() == "Windows" else "pip3"

            for module in missing_modules:
                print(f"Instalando {module}...")
                try:
                    if platform.system() == "Windows":
                        subprocess.run([pip_cmd, "install", module], check=True)
                    else:
                        try:
                            subprocess.run([pip_cmd, "install", module], check=True)
                        except subprocess.SubprocessError:
                            subprocess.run(["sudo", pip_cmd, "install", module], check=True)
                except subprocess.SubprocessError as e:
                    print(f"Error al instalar {module}: {e}")
                    return False

        if platform.system() == "Windows":
            try:
                subprocess.run(["where", "nmap"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.SubprocessError:
                print("Nmap no est\u00e1 instalado o no est\u00e1 en el PATH del sistema.")
                return False
        else:
            try:
                subprocess.run(["which", "nmap"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.SubprocessError:
                print("Nmap no est\u00e1 instalado.")
                subprocess.run(["sudo", "apt-get", "update"], check=True)
                subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)

        return True
    except Exception as e:
        print(f"Error al verificar dependencias: {e}")
        return False

def is_superuser():
    if platform.system() != "Windows":
        return os.geteuid() == 0
    return True

def main():
    print(f"Sistema operativo: {platform.system()} {platform.version()}")
    print(f"Python: {platform.python_version()}")

    if platform.system() != "Windows" and not is_superuser():
        print("No eres superusuario. Reiniciando con permisos de administrador...")
        subprocess.call(["sudo", "python3"] + sys.argv)
        sys.exit()

    if not check_and_install_tkinter():
        print("No se puede iniciar la aplicaci\u00f3n sin tkinter.")
        sys.exit(1)

    if not check_dependencies():
        print("No se puede iniciar la aplicaci\u00f3n debido a dependencias faltantes.")
        sys.exit(1)

    try:
        from gui import start_gui
        start_gui()
    except ImportError as e:
        print(f"Error al importar el m\u00f3dulo gui: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error al iniciar la GUI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
