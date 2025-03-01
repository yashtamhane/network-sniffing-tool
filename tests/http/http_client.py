import socket

server_address = ('127.0.0.1', 8080)
with socket.create_connection(server_address) as sock:
    request = b"GET /test HTTP/1.1\r\nHost: localhost:8080\r\n\r\n"
    sock.sendall(request)
    response = sock.recv(4096)
    print("Received response:\n", response.decode())
