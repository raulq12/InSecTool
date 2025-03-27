import sys
import subprocess
import platform
import os

def check_and_install_tkinter():
    try:
        import tkinter
        return True
    except ImportError:
        print("El módulo tkinter no está instalado. Intentando instalarlo...")
        try:
            # Detectar el sistema operativo
            system = platform.system().lower()
            
            if "linux" in system:
                # En distribuciones basadas en Debian/Ubuntu
                subprocess.run(["sudo", "apt-get", "update"], check=True)
                subprocess.run(["sudo", "apt-get", "install", "-y", "python3-tk"], check=True)
            elif "darwin" in system:  # macOS
                print("En macOS, tkinter debería venir con Python. Intenta reinstalar Python.")
                print("Puedes usar: brew install python-tk  (si tienes Homebrew instalado)")
                return False
            elif "windows" in system:
                print("En Windows, tkinter debería venir con Python.")
                print("Por favor, reinstala Python desde python.org y asegúrate de marcar la opción 'tcl/tk and IDLE'")
                input("Presiona Enter para salir...")
                return False
            else:
                print(f"Sistema operativo no reconocido: {system}")
                return False
                
            print("tkinter instalado correctamente. Reiniciando la aplicación...")
            return True
        except subprocess.SubprocessError as e:
            print(f"Error al instalar tkinter: {e}")
            print("Por favor, instala tkinter manualmente:")
            print("  - En Ubuntu/Debian: sudo apt-get install python3-tk")
            print("  - En Fedora: sudo dnf install python3-tkinter")
            print("  - En Windows: Reinstala Python desde python.org y marca la opción 'tcl/tk and IDLE'")
            input("Presiona Enter para salir...")
            return False

def check_dependencies():
    """Verifica que todas las dependencias estén instaladas"""
    try:
        # Verificar módulos de Python necesarios
        modules_to_check = ["scapy", "nmap", "keyboard"]
        missing_modules = []
        
        for module in modules_to_check:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            print(f"Faltan los siguientes módulos: {', '.join(missing_modules)}")
            print("Intentando instalar los módulos faltantes...")
            
            # En Windows, no usamos sudo
            pip_cmd = "pip" if platform.system() == "Windows" else "pip3"
            
            for module in missing_modules:
                print(f"Instalando {module}...")
                try:
                    if platform.system() == "Windows":
                        subprocess.run([pip_cmd, "install", module], check=True)
                    else:
                        # En Linux/Mac, intentamos primero sin sudo
                        try:
                            subprocess.run([pip_cmd, "install", module], check=True)
                        except subprocess.SubprocessError:
                            # Si falla, intentamos con sudo
                            subprocess.run(["sudo", pip_cmd, "install", module], check=True)
                except subprocess.SubprocessError as e:
                    print(f"Error al instalar {module}: {e}")
                    print(f"Por favor, instala {module} manualmente con: pip install {module}")
                    if platform.system() == "Windows":
                        input("Presiona Enter para salir...")
                    return False
        
        # Verificar nmap en el sistema (especialmente importante en Windows)
        if platform.system() == "Windows":
            try:
                subprocess.run(["where", "nmap"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.SubprocessError:
                print("Nmap no está instalado o no está en el PATH del sistema.")
                print("Por favor, descarga e instala Nmap desde: https://nmap.org/download.html")
                print("Asegúrate de marcar la opción para añadir Nmap al PATH durante la instalación.")
                input("Presiona Enter para salir...")
                return False
        else:  # Linux/Mac
            try:
                subprocess.run(["which", "nmap"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except subprocess.SubprocessError:
                print("Nmap no está instalado.")
                print("Instalando nmap...")
                try:
                    if "darwin" in platform.system().lower():  # macOS
                        subprocess.run(["brew", "install", "nmap"], check=True)
                    else:  # Linux
                        subprocess.run(["sudo", "apt-get", "update"], check=True)
                        subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
                except subprocess.SubprocessError as e:
                    print(f"Error al instalar nmap: {e}")
                    print("Por favor, instala nmap manualmente.")
                    return False
        
        return True
    except Exception as e:
        print(f"Error al verificar dependencias: {e}")
        return False

def main():
    # Mostrar información del sistema
    print(f"Sistema operativo: {platform.system()} {platform.version()}")
    print(f"Python: {platform.python_version()}")
    
    # Verificar si tkinter está instalado
    if not check_and_install_tkinter():
        print("No se puede iniciar la aplicación sin tkinter.")
        sys.exit(1)
    
    # Verificar otras dependencias
    if not check_dependencies():
        print("No se puede iniciar la aplicación debido a dependencias faltantes.")
        sys.exit(1)
    
    # Una vez que tkinter está disponible, importamos la GUI
    try:
        from gui import start_gui
        start_gui()
    except ImportError as e:
        print(f"Error al importar el módulo gui: {e}")
        print("Asegúrate de que el archivo gui.py esté en el mismo directorio.")
        if platform.system() == "Windows":
            input("Presiona Enter para salir...")
        sys.exit(1)
    except Exception as e:
        print(f"Error al iniciar la GUI: {e}")
        if platform.system() == "Windows":
            input("Presiona Enter para salir...")
        sys.exit(1)

# Punto de entrada principal
if __name__ == "__main__":
    main()
