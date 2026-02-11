import socket
import threading
import select

print("🔥 Starting Python Proxy Firewall...")

BLOCKED_KEYWORDS = [
    "youtube",
    "facebook",
    "instagram"
]

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8899


def tunnel(client_socket, remote_socket):
    """
    Bidirectional forwarding between client and remote server
    """
    sockets = [client_socket, remote_socket]

    while True:
        readable, _, _ = select.select(sockets, [], [])

        for sock in readable:
            data = sock.recv(4096)
            if not data:
                return

            if sock is client_socket:
                remote_socket.sendall(data)
            else:
                client_socket.sendall(data)


def handle_client(client_socket):
    try:
        request = client_socket.recv(4096)
        if not request:
            client_socket.close()
            return

        first_line = request.split(b"\r\n")[0]
        print("\n[REQUEST]", first_line)

        if b"CONNECT" in first_line:
            host = first_line.split()[1].decode()
            print("[CHECKING]", host)

            # 🔥 BLOCKING LOGIC
            for keyword in BLOCKED_KEYWORDS:
                if keyword in host.lower():
                    print("[BLOCKED]", host)
                    client_socket.send(
                        b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Python Firewall"
                    )
                    client_socket.close()
                    return

            # 🔥 ALLOW AND CREATE TUNNEL
            remote_host = host.split(":")[0]
            remote_port = int(host.split(":")[1])

            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((remote_host, remote_port))

            client_socket.send(
                b"HTTP/1.1 200 Connection Established\r\n\r\n"
            )

            print("[TUNNEL OPENED]", host)

            tunnel(client_socket, remote_socket)

            remote_socket.close()

        else:
            # Optional: Basic HTTP support (non-HTTPS)
            print("[HTTP REQUEST]")

            client_socket.send(
                b"HTTP/1.1 200 OK\r\n\r\nPython Firewall Running"
            )

    except Exception as e:
        print("Error:", e)

    client_socket.close()


def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(100)

    print(f"🔥 Firewall running at {PROXY_HOST}:{PROXY_PORT}")

    while True:
        client_socket, addr = server.accept()
        print("Connection from", addr)

        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    start_proxy()
