import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import threading

def mostrar_resultado_con_descarga(titulo, mensaje, nombre_archivo):
    """Muestra resultados en ventana con opción a guardar"""
    def guardar_archivo():
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=nombre_archivo,
            filetypes=[("Archivos de texto", "*.txt")]
        )
        if filepath:
            try:
                with open(filepath, "w") as f:
                    f.write(mensaje)
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar: {str(e)}")
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

def crear_entrada_con_label(frame, texto, valor_default="", ancho=20):
    """Crea un label con su entrada"""
    ttk.Label(frame, text=texto).grid(row=len(frame.grid_slaves()), column=0, padx=5, pady=5, sticky="e")
    entry = ttk.Entry(frame, width=ancho)
    entry.insert(0, valor_default)
    entry.grid(row=len(frame.grid_slaves())-1, column=1, padx=5, pady=5, sticky="ew")
    return entry

def crear_boton(frame, texto, comando, colspan=1, pady=5):
    """Crea un botón estilizado"""
    btn = ttk.Button(frame, text=texto, command=comando)
    btn.grid(row=len(frame.grid_slaves()), column=0, columnspan=colspan, pady=pady, sticky="ew")
    return btn

def crear_area_texto(frame, filas=15, columnas=80):
    """Crea un área de texto con scroll"""
    output = scrolledtext.ScrolledText(
        frame,
        wrap=tk.WORD,
        width=columnas,
        height=filas
    )
    output.grid(row=len(frame.grid_slaves()), column=0, columnspan=2, pady=5, sticky="nsew")
    return output

def validar_puerto(puerto_str):
    """Valida que un string sea un puerto válido"""
    try:
        puerto = int(puerto_str)
        return 1 <= puerto <= 65535
    except ValueError:
        return False

def validar_ip(ip):
    """Valida una dirección IP"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def seleccionar_archivo(titulo="Seleccionar archivo", tipos_archivo=(("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*"))):
    """Muestra diálogo para seleccionar archivo"""
    return filedialog.askopenfilename(title=titulo, filetypes=tipos_archivo)