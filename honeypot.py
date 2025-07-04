import socket
import paramiko
import threading
import logging
import cmd

logging.basicConfig(filename='honeypot.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

HOST_KEY = paramiko.RSAKey(filename='server.key')

FAKE_FILESYSTEM = {
    '/': {'type': 'dir', 'content': ['home', 'etc', 'var']},
    '/home': {'type': 'dir', 'content': ['user']},
    '/home/user': {'type': 'dir', 'content': ['password.txt', 'README']},
    '/home/user/password.txt': {'type': 'file', 'content': 'contraseña_super_secreta_123\n'},
    '/home/user/README': {'type': 'file', 'content': 'Este es un sistema señuelo.\n'},
    '/etc': {'type': 'dir', 'content': ['passwd', 'os-release']},
    '/etc/passwd': {'type': 'file', 'content': 'root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n'},
    '/etc/os-release': {'type': 'file', 'content': 'NAME="Arch Linux"\nPRETTY_NAME="Arch Linux"\nID=arch\nBUILD_ID=rolling\nANSI_COLOR="38;2;23;147;209"\nHOME_URL="https://archlinux.org/"\nDOCUMENTATION_URL="https://wiki.archlinux.org/"\nSUPPORT_URL="https://bbs.archlinux.org/"\nBUG_REPORT_URL="https://bugs.archlinux.org/"\nLOGO=archlinux-logo\n'},
    '/var': {'type': 'dir', 'content': ['log']},
    '/var/log': {'type': 'dir', 'content': []}
}

class FakeShell(cmd.Cmd):
    prompt = '$ '

    def __init__(self, channel):
        super().__init__(stdout=channel, stdin=channel)
        self.channel = channel
        self.current_dir = '/home/user'
        self.user = "root"

    def do_ls(self, arg):
        path_to_list = self._get_path(arg) if arg else self.current_dir
        node = FAKE_FILESYSTEM.get(path_to_list)

        if node and node['type'] == 'dir':
            for item in node['content']:
                self.stdout.write(item + '\n')
        else:
            self.stdout.write(f"ls: no se puede acceder a '{arg}': No existe el fichero o el directorio\n")

    def do_cd(self, arg):
        if not arg: return
        
        new_path = self._get_path(arg)
        if FAKE_FILESYSTEM.get(new_path, {}).get('type') == 'dir':
            self.current_dir = new_path
        else:
            self.stdout.write(f"bash: cd: {arg}: No existe el fichero o el directorio\n")

    def do_cat(self, arg):
        if not arg: return
        path = self._get_path(arg)
        node = FAKE_FILESYSTEM.get(path)

        if node and node['type'] == 'file':
            self.stdout.write(node['content'])
        elif node and node['type'] == 'dir':
            self.stdout.write(f"cat: {arg}: Es un directorio\n")
        else:
            self.stdout.write(f"cat: {arg}: No existe el fichero o el directorio\n")
            
    def do_pwd(self, _):
        self.stdout.write(self.current_dir + '\n')

    def do_whoami(self, _):
        self.stdout.write(self.user + '\n')

    def do_exit(self, _):
        self.stdout.write("logout\n")
        self.channel.close()
        return True 
     
    def default(self, line):
        comando = line.split()[0]
        logging.info(f"Comando desconocido ejecutado por {self.channel.getpeername()[0]}: '{line}'")
        self.stdout.write(f"bash: {comando}: orden no encontrada\n")

    def _get_path(self, path):
        if path.startswith('/'):
            return path
        
        new_path_parts = self.current_dir.split('/')
        if self.current_dir == '/': new_path_parts = ['']
            
        for part in path.split('/'):
            if part == '..':
                if len(new_path_parts) > 1:
                    new_path_parts.pop()
            elif part != '.' and part != '':
                new_path_parts.append(part)
        
        return '/'.join(new_path_parts) or '/'

    def do_uname(self, arg):
        if arg == '-a':
            self.stdout.write("Linux arch-server 6.8.9-arch1-1 #1 SMP PREEMPT_DYNAMIC Tue, 27 Jun 2025 18:54:32 +0000 x86_64 GNU/Linux\n")
        else:
            self.stdout.write("Linux\n")

    def do_wget(self, url):
        if not url:
            self.stdout.write("wget: missing URL\n")
            return

        nombre_archivo = url.split('/')[-1] or "index.html"
        
        logging.info(f"Intento de descarga (wget) desde {self.channel.getpeername()[0]}: {url}")
        
        self.stdout.write(f"--2025-07-04 16:55:37--  {url}\n")
        self.stdout.write(f"Resolving {url.split('/')[2]}... 127.0.0.1\n")
        self.stdout.write(f"Connecting to {url.split('/')[2]}|127.0.0.1|:80... connected.\n")
        self.stdout.write("HTTP request sent, awaiting response... 200 OK\n")
        self.stdout.write(f"Length: 12345 (12K) [application/octet-stream]\n")
        self.stdout.write(f"Saving to: '{nombre_archivo}'\n\n")
        self.stdout.write(f"{nombre_archivo}          100%[===================>]  12.06K  --.-KB/s    in 0s\n\n")
        self.stdout.write("2025-07-04 16:55:37 (34.5 MB/s) - ‘index.html’ saved [12345/12345]\n")
        
        path_completo = self.current_dir + '/' + nombre_archivo
        FAKE_FILESYSTEM[path_completo] = {'type': 'file', 'content': '[malware content]'}
        if nombre_archivo not in FAKE_FILESYSTEM[self.current_dir]['content']:
            FAKE_FILESYSTEM[self.current_dir]['content'].append(nombre_archivo)

    def do_id(self, _):
        self.stdout.write("uid=0(root) gid=0(root) groups=0(root)\n")

    def do_w(self, _):
        attacker_ip = self.channel.getpeername()[0]
        from datetime import datetime
        login_time = datetime.now().strftime("%H:%M")
        header = " USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        session_line = f" root     pts/0    {attacker_ip:<16} {login_time}    0.00s  0.02s  0.00s w\n"        
        self.stdout.write(header)
        self.stdout.write(session_line)

    def do_netstat(self, arg):
        if 'a' not in arg or 'n' not in arg or 't' not in arg:
            self.stdout.write("netstat: please use flags like -antp or -ant\n")
            return

        netstat_falso = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:* LISTEN      1010/nginx
tcp        0      0 0.0.0.0:22              0.0.0.0:* LISTEN      879/sshd
tcp        0      0 0.0.0.0:443             0.0.0.0:* LISTEN      1010/nginx
tcp        0      0 127.0.0.1:3306          0.0.0.0:* LISTEN      954/mysqld
tcp        0      0 127.0.0.1:6379          0.0.0.0:* LISTEN      731/redis-server
tcp        0    364 192.168.1.101:22        192.168.1.202:54321     ESTABLISHED 1234/sshd: root
"""
        self.stdout.write(netstat_falso)

    def do_ps(self, arg):
        if arg.strip() != 'aux':
            self.stdout.write("error: unsupported arguments; please use 'ps aux'\n")
            return
            
        procesos_falsos = procesos_falsos = """USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1  22276 13288 ?        Ss   17:38   0:01 /sbin/init
root           2  0.0  0.0      0     0 ?        S    17:38   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   17:38   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   17:38   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   17:38   0:00 [kworker/0:0H-kblockd]
root           9  0.0  0.0      0     0 ?        I<   17:38   0:00 [mm_percpu_wq]
root         115  0.0  0.0      0     0 ?        S    17:38   0:00 [kswapd0]
root         268  0.0  0.2  73212 37404 ?        Ss   17:38   0:00 /usr/lib/systemd/systemd-journald
systemd+     376  0.0  0.0  89900  7552 ?        Ssl  17:38   0:00 /usr/lib/systemd/systemd-timesyncd
root         383  0.0  0.0  36128  9984 ?        Ss   17:38   0:00 /usr/lib/systemd/systemd-udevd
dbus         549  0.0  0.0   8496  3996 ?        Ss   17:38   0:00 /usr/bin/dbus-broker-launch --scope system
dbus         550  0.0  0.0   7804  3248 ?        S    17:38   0:01 dbus-broker --log 4 --controller 9
root         551  0.0  0.1 416740 24928 ?        Ssl  17:38   0:01 /usr/bin/NetworkManager --no-daemon
root         553  0.0  0.0  10084  5300 ?        Ss   17:38   0:00 /usr/lib/bluetooth/bluetoothd
root         554  0.0  0.1  16080  7740 ?        Ss   17:38   0:00 /usr/lib/systemd/systemd-logind
root         658  0.0  0.0  17040 10540 ?        Ss   17:38   0:00 /usr/bin/wpa_supplicant -u -s -O /run/wpa_supplicant
root         879  0.0  0.1  84344  8188 ?        Ss   17:39   0:01 /usr/bin/sshd -D
root        1234  0.0  0.2 105992 10112 ?        Ss   18:05   0:00 sshd: root@pts/0
root        1235  0.0  0.1  14888  5884 pts/0    Ss   18:05   0:00 -bash
root        1256  0.0  0.0  16344  3512 pts/0    R+   18:07   0:00 ps aux
"""
        self.stdout.write(procesos_falsos)

class FakeSSHServer(paramiko.ServerInterface):
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
        shell_thread = threading.Thread(target=lambda: FakeShell(channel).cmdloop())
        shell_thread.daemon = True
        shell_thread.start()
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