import socket
import threading
import ssl
import json
import os
from datetime import datetime
from src.auth.authentication import Authentication
from src.server.ConexionManager import Conexion_Manager
from src.server.http_parser import HTTPParser, HTTPResponse
from src.server.Html import Html
from src.server.session_verification import start_cleanup_thread
from secure.ssl_manager import SSLManager 
from queue import Queue

HOST = "0.0.0.0"
PORT = 8443
WORKER_COUNT = 10
client_queue = Queue()

_parser = HTTPParser()
count_manager = Authentication()
ssl_manager = SSLManager()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR = os.path.join(BASE_DIR, 'web')

def serialize_datetime(obj):
    """Función helper para serializar objetos datetime en JSON"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def verify_admin_session(request, client_ip):
    """Verifica que la sesión sea válida y pertenezca al usuario admin"""
    session_id = request.cookies.get('session_id')
    if not session_id:
        return False, None
    
    valid, username = count_manager.validate_session(session_id, client_ip)
    if not valid or username != 'admin':
        return False, username
    
    return True, username

def send_json_response(client, data, status_code=200):
    """Helper para enviar respuestas JSON"""
    response_data = json.dumps(data, default=serialize_datetime)
    response = HTTPResponse(status_code, body=response_data)
    response.headers['Content-Type'] = 'application/json'
    client.sendall(response.to_bytes())

def send_error_json(client, error_message, status_code=400):
    """Helper para enviar errores JSON"""
    send_json_response(client, {"success": False, "error": error_message}, status_code)

def handle_client(client: socket.socket, addr):
    if ssl_manager.enable_https:
        try:
            client = ssl_manager.wrap_client_socket(client)
        except (ssl.SSLError, socket.timeout):
            return
        except Exception as e:
            print(f"Error no esperado en SSL wrap: {e}")
            return
    
    try:
        raw_data = client.recv(8192)
        if not raw_data:
            client.close()
            return

        request = _parser.parse_request(raw_data)

        # ========== MÉTODOS GET ==========
        if request.method == "GET":
            static_files = {
                '/': 'index.html',
                '/index.html': 'index.html',
                '/success.html': 'success.html',
                '/admin.html': 'admin.html',
                '/style.css': 'style.css',
                '/script.js': 'script.js'
            }
            
            if request.path in static_files:
                file_name = static_files[request.path]
                file_path = os.path.join(WEB_DIR, file_name)
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    
                    content_type = 'text/html'
                    if file_name.endswith('.css'):
                        content_type = 'text/css'
                    elif file_name.endswith('.js'):
                        content_type = 'application/javascript'
                    
                    response = _parser.build_static_response(content, content_type)
                    client.sendall(response.to_bytes())
                except FileNotFoundError:
                    response = _parser.build_error_response(404, "Archivo no encontrado")
                    client.sendall(response.to_bytes())
            else:
                response = _parser.build_html_response(Html.html_login)
                client.sendall(response.to_bytes())
            
            client.close()
            return

        # ========== MÉTODOS POST ==========
        if request.method == "POST":
            try:
                mac = Conexion_Manager.get_mac(addr[0])
            except:
                mac = "00:00:00:00:00:00"

            # ===== LOGIN PRINCIPAL =====
            if request.path == '/':
                user = request.form_data.get('user', '')
                password = request.form_data.get('pass', '')
                
                valido, error, sesion_id = count_manager.login(user, password, addr[0], mac)
                
                if not valido:
                    response = _parser.build_error_response(400, error)
                    client.sendall(response.to_bytes())
                else:
                    Conexion_Manager.permitir_usuario(addr[0], mac)
                    response = _parser.build_html_response(Html.html_ok)
                    response.set_cookie('session_id', sesion_id, max_age=3600)
                    client.sendall(response.to_bytes())
            
            # ===== API LOGIN =====
            elif request.path == '/api/login':
                user = request.form_data.get('user', '')
                password = request.form_data.get('pass', '')
                
                valido, error, sesion_id = count_manager.login(user, password, addr[0], mac)
                
                if not valido:
                    send_error_json(client, error, 401)
                else:
                    Conexion_Manager.permitir_usuario(addr[0], mac)
                    response_data = {
                        "success": True, 
                        "message": "Login exitoso",
                        "session_id": sesion_id,
                        "is_admin": user == "admin"
                    }
                    response = HTTPResponse(200, body=json.dumps(response_data))
                    response.headers['Content-Type'] = 'application/json'
                    response.set_cookie('session_id', sesion_id, max_age=3600)
                    client.sendall(response.to_bytes())
            
            # ===== API VERIFY SESSION =====
            elif request.path == '/api/verify-session':
                session_id = request.cookies.get('session_id')
                valid, username = count_manager.validate_session(session_id, addr[0])
                
                if valid:
                    send_json_response(client, {
                        "valid": True,
                        "username": username,
                        "is_admin": username == "admin"
                    })
                else:
                    send_json_response(client, {"valid": False})
            
            # ===== API LISTAR USUARIOS =====
            elif request.path == '/api/users':
                is_admin, username = verify_admin_session(request, addr[0])
                if not is_admin:
                    send_error_json(client, "No autorizado", 403)
                else:
                    try:
                        users = count_manager.user_manager.list_users()
                        send_json_response(client, {"success": True, "users": users})
                    except Exception as e:
                        print(f"Error en /api/users: {e}")
                        send_error_json(client, "Error interno del servidor", 500)
            
            # ===== API CREAR USUARIO =====
            elif request.path == '/api/users/create':
                is_admin, _ = verify_admin_session(request, addr[0])
                if not is_admin:
                    send_error_json(client, "No autorizado", 403)
                else:
                    username = request.form_data.get('username', '').strip()
                    password = request.form_data.get('password', '')
                    
                    if not username or not password:
                        send_error_json(client, "Usuario y contraseña requeridos")
                    elif len(password) < 8:
                        send_error_json(client, "La contraseña debe tener al menos 8 caracteres")
                    else:
                        success, message = count_manager.create_user(username, password, True)
                        if success:
                            send_json_response(client, {"success": True, "message": message})
                        else:
                            send_error_json(client, message)
            
            # ===== API DESACTIVAR USUARIO =====
            elif request.path == '/api/users/deactivate':
                is_admin, _ = verify_admin_session(request, addr[0])
                if not is_admin:
                    send_error_json(client, "No autorizado", 403)
                else:
                    username = request.form_data.get('username', '').strip()
                    
                    if not username:
                        send_error_json(client, "Usuario requerido")
                    elif username == 'admin':
                        send_error_json(client, "No se puede desactivar al usuario admin")
                    else:
                        success, message = count_manager.deactivate_user(username)
                        if success:
                            send_json_response(client, {"success": True, "message": message})
                        else:
                            send_error_json(client, message)
            
            # ===== API ACTIVAR USUARIO =====
            elif request.path == '/api/users/activate':
                is_admin, _ = verify_admin_session(request, addr[0])
                if not is_admin:
                    send_error_json(client, "No autorizado", 403)
                else:
                    username = request.form_data.get('username', '').strip()
                    
                    if not username:
                        send_error_json(client, "Usuario requerido")
                    else:
                        if not count_manager.user_manager.user_exists(username):
                            send_error_json(client, "Usuario no encontrado")
                        else:
                            success = count_manager.user_manager.activate_user(username)
                            if success:
                                send_json_response(client, {
                                    "success": True, 
                                    "message": f"Usuario {username} activado exitosamente"
                                })
                            else:
                                send_error_json(client, "Error al activar usuario")
            
            # ===== API ELIMINAR USUARIO =====
            elif request.path == '/api/users/delete':
                is_admin, _ = verify_admin_session(request, addr[0])
                if not is_admin:
                    send_error_json(client, "No autorizado", 403)
                else:
                    username = request.form_data.get('username', '').strip()
                    
                    if not username:
                        send_error_json(client, "Usuario requerido")
                    elif username == 'admin':
                        send_error_json(client, "No se puede eliminar al usuario admin")
                    else:
                        if not count_manager.user_manager.user_exists(username):
                            send_error_json(client, "Usuario no encontrado")
                        else:
                            # Cerrar todas las sesiones del usuario antes de eliminarlo
                            count_manager.logout_user(username)
                            # Eliminar el usuario
                            success = count_manager.user_manager.delete_user(username)
                            if success:
                                send_json_response(client, {
                                    "success": True, 
                                    "message": f"Usuario {username} eliminado exitosamente"
                                })
                            else:
                                send_error_json(client, "Error al eliminar usuario")
            
            # ===== API LISTAR SESIONES =====
            elif request.path == '/api/sessions':
                is_admin, _ = verify_admin_session(request, addr[0])
                if not is_admin:
                    send_error_json(client, "No autorizado", 403)
                else:
                    try:
                        sessions = count_manager.get_active_sessions()
                        send_json_response(client, {"success": True, "sessions": sessions})
                    except Exception as e:
                        print(f"Error en /api/sessions: {e}")
                        send_error_json(client, "Error interno del servidor", 500)
            
            # ===== API TERMINAR SESIÓN =====
            elif request.path == '/api/sessions/terminate':
                is_admin, _ = verify_admin_session(request, addr[0])
                if not is_admin:
                    send_error_json(client, "No autorizado", 403)
                else:
                    session_id = request.form_data.get('session_id', '').strip()
                    
                    if not session_id:
                        send_error_json(client, "ID de sesión requerido")
                    else:
                        # Obtener información de la sesión antes de eliminarla
                        session_info = None
                        if session_id in count_manager.session_manager.sessions:
                            session_info = count_manager.session_manager.sessions[session_id]
                        
                        success = count_manager.logout(session_id)
                        
                        # Si había información de la sesión, bloquear al usuario
                        if success and session_info:
                            client_ip = session_info.get('client_ip')
                            client_mac = session_info.get('client_mac')
                            if client_ip and client_mac:
                                try:
                                    Conexion_Manager.bloquear_usuario(client_ip, client_mac)
                                except Exception as e:
                                    print(f"Error al bloquear usuario: {e}")
                        
                        if success:
                            send_json_response(client, {
                                "success": True, 
                                "message": "Sesión terminada exitosamente"
                            })
                        else:
                            send_error_json(client, "Error al terminar sesión o sesión no encontrada")
            
            # ===== RUTA NO ENCONTRADA =====
            else:
                response = _parser.build_error_response(404, "Ruta no encontrada")
                client.sendall(response.to_bytes())

    except Exception as e:
        print(f"Error en handle_client: {e}")
        import traceback
        traceback.print_exc()
        try:
            response = _parser.build_error_response(500, "Error interno del servidor")
            client.sendall(response.to_bytes())
        except:
            pass
    finally:
        try:
            client.close()
        except:
            pass

def worker():
    while True:
        client, addr = client_queue.get()
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

# Inicializar servidor
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server = ssl_manager.wrap_server_socket(server)
server.listen(50)

# Iniciar pool de workers y limpieza de sesiones
start_thread_pool()
start_cleanup_thread(count_manager)

# Crear usuario admin por defecto
try:
    count_manager.create_user("admin", "12345678")
    print("Usuario admin creado/verificado")
except:
    print("Usuario admin ya existe")

print(f"Servidor captivo escuchando en {HOST}:{PORT}")
print(f"HTTPS habilitado: {ssl_manager.enable_https}")

# Loop principal
while True:
    try:
        client, addr = server.accept()
        client_queue.put((client, addr))
    except KeyboardInterrupt:
        print("\nCerrando servidor...")
        break
    except Exception as e:
        print(f"Error aceptando conexión: {e}")