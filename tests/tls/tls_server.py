import socket
import ssl

server_address = ('127.0.0.1', 8443)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(server_address)
    sock.listen(5)
    print("TLS server running on {}:{}".format(*server_address))
    while True:
        client_socket, addr = sock.accept()
        try:
            with context.wrap_socket(client_socket, server_side=True) as tls_conn:
                print("Accepted connection from", addr)
                data = tls_conn.recv(1024)
                print("Received:", data)
                tls_conn.sendall(b"HTTP/1.1 200 OK\r\n\r\nHello from TLS server!")
        except Exception as e:
            print("Error handling connection:", e)
