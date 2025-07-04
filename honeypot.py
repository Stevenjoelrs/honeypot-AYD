import socket
import paramiko
import threading
import logging

logging.basicConfig(filename='honeypot.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

HOST_KEY = paramiko.RSAKey(filename='server.key')

class FakeSSHServer(paramiko.ServerInterface):
    """Maneja la autenticación y los canales SSH."""
    def __init__(self, client_address):
        self.client_address = client_address

    def check_auth_password(self, username, password):
        logging.info(f"[!] Intento de login: {self.client_address[0]} user='{username}' pass='{password}'")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        channel.send("Hola!\n")
        channel.close()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

def start_server(port=2222):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))
        sock.listen(100)
        logging.info(f"[*] Servidor escuchando en el puerto {port}...")

        while True:
            try:
                client, addr = sock.accept()
                logging.info(f"[+] Nueva conexión de {addr[0]}:{addr[1]}")
                
                transport = paramiko.Transport(client)
                transport.add_server_key(HOST_KEY)
                server = FakeSSHServer(addr)
                
                handler_thread = threading.Thread(
                    target=transport.start_server, 
                    args=(server,)
                )
                handler_thread.daemon = True
                handler_thread.start()

            except Exception as e:
                logging.error(f"[-] Error al manejar conexión: {e}")

    except Exception as e:
        logging.error(f"[-] Error fatal al iniciar el servidor: {e}")

if __name__ == "__main__":
    start_server()