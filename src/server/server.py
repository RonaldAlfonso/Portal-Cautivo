import socket
import threading
from src.auth.authentication import Authentication
from src.server.ConexionManager import Conexion_Manager
from src.server.http_parser import HTTPParser

HOST = "10.42.0.1"
PORT = 8080

_parser = HTTPParser()
count_manager = Authentication()

html_login = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Portal Cautivo</title>
</head>
<body>
<h1>Acceso requerido</h1>
<form id="loginForm">
  <label>Usuario:</label><br>
  <input type="text" id="user" name="user"><br><br>

  <label>Contraseña:</label><br>
  <input type="password" id="pass" name="pass"><br><br>

  <button type="submit">Entrar</button>
</form>

<script>
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const user = document.getElementById('user').value;
    const pass = document.getElementById('pass').value;

    const response = await fetch('/', {
        method: 'POST',
        headers: {
            'user': user,
            'pass': pass
        }
    });

    const text = await response.text();
    document.body.innerHTML = text;
});
</script>
</body>
</html>
"""

html_ok = """
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>OK</title></head>
<body>
<h1>Acceso concedido</h1>
<p>Ya puedes navegar.</p>
</body>
</html>
"""

def handle_client(client: socket.socket, addr):
    try:
        raw_data = client.recv(8192)
        if not raw_data:
            client.close()
            return

        request = _parser.parse_request(raw_data)

        # --- GET → devolver formulario ---
        if request.method == "GET":
            response = _parser.build_html_response(html_login)
            client.sendall(response.to_bytes())
            client.close()
            return

        # --- POST → validar usuario ---
        if request.method == "POST":
            user = request.headers.get("user", "")
            password = request.headers.get("pass", "")
            print(user)
            print(password)

            valido, error, sesion_id = count_manager.login(password, user, addr[0])
            if(user=="admin" and password=="1234"):
                valido=True
            print(valido)
            if not valido:
                response = _parser.build_error_response(400, error)
                client.sendall(response.to_bytes())
            else:
                Conexion_Manager.permitir_usuario(addr[0])
                response = _parser.build_html_response(html_ok)
                client.sendall(response.to_bytes())

    except Exception as e:
        print("Error:", e)
    finally:
        client.close()


# --- Servidor principal con threads ---
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(50)
count_manager.create_user("admin","1234")
print(f"Servidor captivo escuchando en {HOST}:{PORT}")

while True:
    client, addr = server.accept()
    threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
