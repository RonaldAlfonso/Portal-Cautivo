import ssl
import socket
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

class SSLManager:
    def __init__(self, 
                 certfile: str = "ssl/server.crt", 
                 keyfile: str = "ssl/server.key",
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
            result_key = subprocess.run([
                'openssl', 'genrsa', '-out', self.keyfile, '2048'
            ], check=True, capture_output=True, text=True)
            
            result_cert = subprocess.run([
                'openssl', 'req', '-new', '-x509', '-key', self.keyfile,
                '-out', self.certfile, '-days', '365', '-subj',
                '/CN=captive-portal.local/O=Captive Portal/C=CU'
            ], check=True, capture_output=True, text=True)
            
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
                except OSError as cleanup_error:
                    logger.debug(f"Error limpiando {file_path}: {cleanup_error}")
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
        
        try:
            secure_socket = self.context.wrap_socket(
                plain_socket, 
                server_side=True,
                do_handshake_on_connect=True
            )
            logger.debug("Socket envuelto correctamente con SSL")
            return secure_socket
            
        except ssl.SSLError as e:
            logger.error(f"Error envolviendo socket SSL: {e}")
            try:
                plain_socket.close()
            except OSError as close_error:
                logger.debug(f"Error cerrando socket: {close_error}")
            raise RuntimeError(f"No se pudo establecer conexión SSL segura: {e}")
    
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