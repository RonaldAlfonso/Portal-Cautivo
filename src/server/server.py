import socket

HOST = "127.0.0.1"  # escucha en todas las interfaces
PORT = 8080         # puerto HTTP estándar (necesita sudo)

html = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Mi Portal Cautivo</title>
</head>
<body>
<h1>Bienvenido!</h1>
<p>Esta es la página que siempre voy a devolver.</p>
</body>
</html>
"""

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(20)

print(f"Servidor captivo escuchando en {HOST}:{PORT}")

while True:
    client, addr = server.accept()
    print("Conexión:", addr)

    request = client.recv(2048).decode(errors="ignore")
    print("Peticiones:", request.split("\n")[0])  # solo la primera línea

    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "Pragma: no-cache\r\n"
        "Expires: 0\r\n"
        "\r\n" +
        html
    )

    client.sendall(response.encode())
    client.close()
