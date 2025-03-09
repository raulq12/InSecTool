import tkinter as tk
from tkinter import ttk, messagebox

def toggle_ip_input(command):
    for widget in target_frame.winfo_children():
        widget.destroy()
    
    if command:
        target_label = tk.Label(target_frame, text="IP Objetivo:", font=("Helvetica", 12), bg="#121212", fg="white")
        target_label.pack()
        ip_entry = tk.Entry(target_frame, font=("Helvetica", 12), width=20)
        ip_entry.pack()
        
        start_button = ttk.Button(target_frame, text="Iniciar", command=lambda: command(ip_entry.get()), style="TButton")
        start_button.pack(pady=5)
        
        target_frame.pack(pady=10)
    else:
        target_frame.pack_forget()

def open_port_scanner(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Escaneo de Puertos", f"Escaneando puertos en {ip}...")

def open_sniffer():
    toggle_ip_input(None)
    messagebox.showinfo("Sniffer de Red", "Herramienta de sniffer de red seleccionada.")

def open_reverse_shell():
    toggle_ip_input(None)
    messagebox.showinfo("Shell Inversa", "Herramienta de shell inversa seleccionada.")

def open_network_scan(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Detección de Máquinas", f"Escaneando red en {ip}...")

def open_ddos_attack(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Ataque DDoS", f"Iniciando ataque DDoS contra {ip}...")

def open_brute_force(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Fuerza Bruta", f"Iniciando ataque de fuerza bruta en {ip}...")

def open_mitm(ip):
    if not ip:
        messagebox.showerror("Error", "Por favor, ingresa una IP objetivo.")
        return
    messagebox.showinfo("Man in the Middle", f"Iniciando ataque MITM en {ip}...")

def open_keylogger():
    toggle_ip_input(None)
    messagebox.showinfo("Keylogger", "Herramienta de keylogger seleccionada.")

root = tk.Tk()
root.title("NetSecTools - Pentesting")
root.geometry("500x500")
root.configure(bg="#121212")

style = ttk.Style()
style.configure("TButton", font=("Helvetica", 12), padding=10, background="#ff0000", foreground="white")

header_label = tk.Label(root, text="NetSecTools", font=("Helvetica", 24, "bold"), bg="#121212", fg="#ff0000")
header_label.pack(pady=10)

target_frame = tk.Frame(root, bg="#121212")
target_frame.pack_forget()

button_frame = tk.Frame(root, bg="#121212")
button_frame.pack(pady=10)

buttons = [
    ("Escaneo de Puertos", lambda: toggle_ip_input(open_port_scanner)),
    ("Sniffer de Red", open_sniffer),
    ("Shell Inversa", open_reverse_shell),
    ("Detección de Máquinas", lambda: toggle_ip_input(open_network_scan)),
    ("Ataque DDoS", lambda: toggle_ip_input(open_ddos_attack)),
    ("Fuerza Bruta", lambda: toggle_ip_input(open_brute_force)),
    ("Man in the Middle", lambda: toggle_ip_input(open_mitm)),
    ("Keylogger", open_keylogger),
]

for i in range(0, len(buttons), 2):
    row_frame = tk.Frame(button_frame, bg="#121212")
    row_frame.pack(fill=tk.X, padx=20, pady=5)
    for j in range(2):
        if i + j < len(buttons):
            text, command = buttons[i + j]
            btn = ttk.Button(row_frame, text=text, command=command, style="TButton")
            btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)


root.mainloop()
