import tkinter as tk
from tkinter import filedialog

def mostrar_resultado_con_descarga(titulo, mensaje, nombre_archivo):
    def guardar_archivo():
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=nombre_archivo,
            filetypes=[("Archivos de texto", "*.txt")]
        )
        if filepath:
            with open(filepath, "w") as f:
                f.write(mensaje)
        ventana.destroy()
    
    ventana = tk.Toplevel()
    ventana.title(titulo)
    
    scroll = tk.Scrollbar(ventana)
    scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    text = tk.Text(ventana, yscrollcommand=scroll.set)
    text.insert(tk.END, mensaje)
    text.config(state=tk.DISABLED)
    text.pack(fill=tk.BOTH, expand=True)
    
    scroll.config(command=text.yview)
    
    tk.Button(
        ventana,
        text="Guardar y Salir",
        command=guardar_archivo
    ).pack(pady=10)