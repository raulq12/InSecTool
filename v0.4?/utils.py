import tkinter as tk

def mostrar_resultado_con_descarga(titulo, mensaje, nombre_archivo):
    """
    Muestra una ventana de mensaje con dos botones: "Salir" y "Descargar y Salir".
    Si se hace clic en "Descargar y Salir", se crea un archivo .txt con el mensaje.
    
    :param titulo: Título de la ventana.
    :param mensaje: Mensaje a mostrar en la ventana.
    :param nombre_archivo: Nombre del archivo .txt a crear.
    """
    def descargar_y_salir():
        # Crear el archivo .txt
        with open(nombre_archivo, "w", encoding="utf-8") as archivo:
            archivo.write(mensaje)
        ventana.destroy()  # Cerrar la ventana

    def salir():
        ventana.destroy()  # Cerrar la ventana sin hacer nada

    # Crear una ventana personalizada
    ventana = tk.Toplevel()
    ventana.title(titulo)
    
    # Mostrar el mensaje
    mensaje_label = tk.Label(ventana, text=mensaje, font=("Helvetica", 12), padx=20, pady=20)
    mensaje_label.pack()

    # Crear los botones
    boton_descargar = tk.Button(ventana, text="Descargar y Salir", command=descargar_y_salir, bg="#4CAF50", fg="white")
    boton_descargar.pack(side=tk.LEFT, padx=10, pady=10)

    boton_salir = tk.Button(ventana, text="Salir", command=salir, bg="#FF5722", fg="white")
    boton_salir.pack(side=tk.RIGHT, padx=10, pady=10)

    # Centrar la ventana en la pantalla
    ventana.update_idletasks()
    ancho = ventana.winfo_width()
    alto = ventana.winfo_height()
    x = (ventana.winfo_screenwidth() // 2) - (ancho // 2)
    y = (ventana.winfo_screenheight() // 2) - (alto // 2)
    ventana.geometry(f"{ancho}x{alto}+{x}+{y}")

    # Hacer que la ventana sea modal
    ventana.grab_set()
    ventana.wait_window()