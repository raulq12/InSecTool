import sys
import subprocess

def check_and_install_tkinter():
    try:
        import tkinter
        return True
    except ImportError:
        print("El módulo tkinter no está instalado. Intentando instalarlo...")
        try:
            # Detectar el sistema operativo
            import platform
            system = platform.system().lower()
            
            if "linux" in system:
                # En distribuciones basadas en Debian/Ubuntu
                subprocess.run(["sudo", "apt-get", "update"], check=True)
                subprocess.run(["sudo", "apt-get", "install", "-y", "python3-tk"], check=True)
            elif "darwin" in system:  # macOS
                print("En macOS, tkinter debería venir con Python. Intenta reinstalar Python.")
                return False
            elif "windows" in system:
                print("En Windows, tkinter debería venir con Python. Intenta reinstalar Python.")
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
            print("  - En Windows/macOS: Reinstala Python asegurándote de incluir tkinter")
            return False

def main():
    # Verificar si tkinter está instalado
    if not check_and_install_tkinter():
        print("No se puede iniciar la aplicación sin tkinter.")
        sys.exit(1)
    
    # Una vez que tkinter está disponible, importamos la GUI
    try:
        from gui import start_gui
        start_gui()
    except ImportError as e:
        print(f"Error al importar el módulo gui: {e}")
        print("Asegúrate de que el archivo gui.py esté en el mismo directorio.")
        sys.exit(1)

# Punto de entrada principal
if __name__ == "__main__":
    main()
