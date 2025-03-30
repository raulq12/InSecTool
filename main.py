import subprocess
import sys

def run_requirements():
    try:
        subprocess.run(["python3", "requeriments.py"], check=True)
        return True
    except subprocess.CalledProcessError:
        print("Error al verificar e instalar dependencias.")
        return False

def main():
    if not run_requirements():
        sys.exit(1)

    try:
        from gui import start_gui
        start_gui()
    except ImportError as e:
        print(f"Error al importar el módulo GUI: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error al iniciar la GUI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
