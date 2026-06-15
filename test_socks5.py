import socket
import threading
import struct

def handle_client(client):
    print("DEBUG: client connected")
    try:
        # Handshake
        data = client.recv(2)
        if data[0] != 5:
            return
        nmethods = data[1]
        if nmethods:
            client.recv(nmethods)
        client.send(b'\x05\x00')
        print("DEBUG: handshake done")

        # Request
        data = client.recv(4)
        if data[1] != 1:  # CONNECT
            return
        atyp = data[3]
        if atyp == 1:  # IPv4
            addr = socket.inet_ntoa(client.recv(4))
        elif atyp == 3:  # domain
            dlen = client.recv(1)[0]
            addr = client.recv(dlen).decode()
        else:
            return
        port = struct.unpack('!H', client.recv(2))[0]
        print(f"DEBUG: CONNECT {addr}:{port}")

        # Подключаемся к целевому хосту
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((addr, port))

        # Ответ прокси
        bind_addr = ("0.0.0.0", 0)
        bind_bytes = socket.inet_aton(bind_addr[0]) + struct.pack("!H", bind_addr[1])
        client.send(b'\x05\x00\x00\x01' + bind_bytes)
        print("DEBUG: success response sent")

        # Мост
        def forward(src, dst):
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        t1 = threading.Thread(target=forward, args=(client, remote))
        t2 = threading.Thread(target=forward, args=(remote, client))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as e:
        print(f"DEBUG error: {e}")
    finally:
        client.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 1080))
server.listen(5)
print("SOCKS5 test server listening on 127.0.0.1:1080")
while True:
    client, addr = server.accept()
    threading.Thread(target=handle_client, args=(client,)).start()
