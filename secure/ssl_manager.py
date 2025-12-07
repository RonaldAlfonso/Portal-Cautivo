import ssl
import socket
import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

class SSLManager:
    def __init__(self, 
                 certfile: str = "secure/server.crt", 
                 keyfile: str = "secure/server.key",
                 enable_https: bool = True):
        
        self.certfile = self._validate_file_path(certfile)
        self.keyfile = self._validate_file_path(keyfile)
        self.enable_https = enable_https
        self.context = None
        
        if self.enable_https:
            self._ensure_certificates_exist()
            self._setup_ssl_context()
    
    def _validate_file_path(self, file_path: str) -> str:
        path = Path(file_path)
        if '..' in path.parts:
            raise ValueError(f"Ruta de archivo insegura: {file_path}")
        return file_path
    
    def _ensure_certificates_exist(self) -> None:
        ssl_dir = Path(self.certfile).parent
        try:
            ssl_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as e:
            logger.error(f"No se pudo crear directorio SSL: {e}")
            self.enable_https = False
            return
        
        cert_exists = os.path.exists(self.certfile)
        key_exists = os.path.exists(self.keyfile)
        
        if not cert_exists or not key_exists:
            logger.warning("Certificados SSL no encontrados, generando autofirmados...")
            self._generate_self_signed_cert()
        else:
            self._validate_existing_cert_permissions()
    
    def _validate_existing_cert_permissions(self) -> None:
        try:
            key_mode = os.stat(self.keyfile).st_mode & 0o777
            if key_mode != 0o600:
                logger.warning(f"Permisos inseguros en clave privada: {oct(key_mode)}, corrigiendo...")
                os.chmod(self.keyfile, 0o600)
        except OSError as e:
            logger.error(f"Error validando permisos: {e}")
    
    def _generate_self_signed_cert(self) -> None:
        try:
            server_ip = "10.42.0.1"
            
            result_key = subprocess.run([
                'openssl', 'genrsa', '-out', self.keyfile, '2048'
            ], check=True, capture_output=True, text=True)
            
            csr_config = f"""[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = {server_ip}
O = Portal Cautivo
C = CU

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = captive-portal.local
IP.1 = 127.0.0.1
IP.2 = {server_ip}
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cnf', delete=False) as f:
                f.write(csr_config)
                config_file = f.name
            
            result_cert = subprocess.run([
                'openssl', 'req', '-new', '-x509', '-key', self.keyfile,
                '-out', self.certfile, '-days', '365',
                '-config', config_file
            ], check=True, capture_output=True, text=True)
            
            os.unlink(config_file)
            
            if not os.path.exists(self.keyfile) or not os.path.exists(self.certfile):
                raise RuntimeError("Los archivos de certificado no se crearon")
            
            os.chmod(self.keyfile, 0o600)
            os.chmod(self.certfile, 0o644)
            
            logger.info("Certificados autofirmados generados correctamente")
            
        except (subprocess.CalledProcessError, FileNotFoundError, RuntimeError) as e:
            logger.error(f"No se pudo generar certificados: {e}")
            if isinstance(e, subprocess.CalledProcessError):
                logger.error(f"Error OpenSSL (salida): {e.stderr}")
            
            for file_path in [self.keyfile, self.certfile]:
                try:
                    if os.path.exists(file_path):
                        os.unlink(file_path)
                except OSError:
                    pass
            
            self.enable_https = False
    
    def _setup_ssl_context(self) -> None:
        try:
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            
            self.context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS:!DHE')
            self.context.options |= ssl.OP_NO_SSLv2
            self.context.options |= ssl.OP_NO_SSLv3
            self.context.options |= ssl.OP_NO_TLSv1
            self.context.options |= ssl.OP_NO_TLSv1_1
            
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
            
            logger.info("Contexto SSL configurado correctamente")
            
        except ssl.SSLError as e:
            logger.error(f"Error configurando SSL: {e}")
            self.enable_https = False
        except FileNotFoundError as e:
            logger.error(f"Archivos de certificado no encontrados: {e}")
            self.enable_https = False
    
    def wrap_server_socket(self, plain_socket: socket.socket) -> socket.socket:
        if not self.enable_https or not self.context:
            logger.error("HTTPS CRÍTICAMENTE DESACTIVADO - El servidor funciona SIN cifrado")
            return plain_socket
        
        logger.info("Socket del servidor listo para conexiones SSL")
        return plain_socket
    
    def wrap_client_socket(self, client_socket: socket.socket):
        if not self.enable_https or not self.context:
            return client_socket
        
        try:
            secure_socket = self.context.wrap_socket(
                client_socket,
                server_side=True,
                do_handshake_on_connect=False
            )
            secure_socket.settimeout(5.0)
            secure_socket.do_handshake()
            secure_socket.settimeout(None)
            return secure_socket
        except ssl.SSLError as e:
            logger.warning(f"Error en handshake SSL: {e}")
            try:
                client_socket.close()
            except:
                pass
            raise
    
    def get_https_info(self) -> dict:
        info = {
            'https_enabled': self.enable_https,
            'certificate_file': self.certfile if self.enable_https else None,
            'key_file': self.keyfile if self.enable_https else None,
            'has_valid_context': self.context is not None
        }
        
        if not self.enable_https:
            logger.critical("HTTPS DESACTIVADO - Todas las comunicaciones son INSEGURAS")
            
        return info
    
    def validate_connection(self, ssl_socket: ssl.SSLSocket) -> bool:
        if not isinstance(ssl_socket, ssl.SSLSocket):
            return False
        
        try:
            cipher = ssl_socket.cipher()
            if cipher is None:
                return False
                
            protocol = ssl_socket.version()
            logger.debug(f"Conexión SSL: {protocol} con cifrado {cipher[0]}")
            return True
        except (ssl.SSLError, AttributeError, OSError):
            return False