import socket
import paramiko
import threading

HOST_KEY = paramiko.RSAKey(filename='server.key')

def start_server(port=2222):
    """Uso de un puerto especifico"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))
        sock.listen(100)
        print(f"[*] Escuchando el puerto {port}...")

        while True:
            client, addr = sock.accept()
            print(f"[+] Nueva conexión de {addr[0]}:{addr[1]}")
            








    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    start_server()
