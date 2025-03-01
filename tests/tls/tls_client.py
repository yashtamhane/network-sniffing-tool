import socket
import ssl

server_address = ('127.0.0.1', 8443)

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection(server_address) as sock:
    with context.wrap_socket(sock, server_hostname='localhost') as tls_sock:
        print("Connected with TLS version:", tls_sock.version())
        request = b"GET / HTTP/1.1\r\nHost: localhost:8443\r\n\r\n"
        tls_sock.sendall(request)
        response = tls_sock.recv(4096)
        print("Received response:\n", response.decode())
