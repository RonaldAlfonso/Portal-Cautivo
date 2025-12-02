import socket
import threading
from src.auth.authentication import Authentication
from src.server.ConexionManager import Conexion_Manager
from src.server.http_parser import HTTPParser
from src.server.Html import Html
from src.server.session_verification import start_cleanup_thread
from ssl.ssl_manager import SSLManager 
from queue import Queue
HOST = "127.0.0.1" #"10.42.0.1"
PORT = 8080
WORKER_COUNT = 10
client_queue = Queue()

_parser = HTTPParser()
count_manager = Authentication()
ssl_manager=SSLManager()



def handle_client(client: socket.socket, addr):
    try:
        raw_data = client.recv(8192)
        if not raw_data:
            client.close()
            return

        request = _parser.parse_request(raw_data)
        request._parse_form_data()

        # --- GET → devolver formulario ---
        if request.method == "GET":
            response = _parser.build_html_response(Html.html_login)
            client.sendall(response.to_bytes())
            client.close()
            return

        # --- POST → validar usuario ---
        if request.method == "POST":
            form=request._parse_form_data()
            user=form['user']
            password=form['pass']
            
            print(user)
            print(password)
            

            valido, error, sesion_id = count_manager.login(user, password, addr[0])
            # if(user=="admin" and password=="1234"):
            #     valido=True
            print(valido)
            if not valido:
                response = _parser.build_error_response(400, error)
                client.sendall(response.to_bytes())
            else:
                mac=Conexion_Manager.get_mac(addr[0])
                Conexion_Manager.permitir_usuario(addr[0],mac)
                response = _parser.build_html_response(Html.html_ok)
                client.sendall(response.to_bytes())

    except Exception as e:
        print("Error:", e)
    finally:
        client.close()


def worker():
    """Worker que atiende clientes de la cola."""
    while True:
        client, addr = client_queue.get()   # Espera un cliente
        try:
            handle_client(client, addr)
        except Exception as e:
            print(f"Error manejando {addr}: {e}")
        finally:
          
            client_queue.task_done()  


def start_thread_pool():
    
    for _ in range(WORKER_COUNT):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        
# --- Servidor principal con threads ---
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server=ssl_manager.wrap_server_socket(server)
server.listen(50)
start_thread_pool()
start_cleanup_thread(count_manager)
count_manager.create_user("admin","12345678")
print(f"Servidor captivo escuchando en {HOST}:{PORT}")

while True:
    client, addr = server.accept()
    client_queue.put((client, addr))
    


