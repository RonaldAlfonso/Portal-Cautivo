import logging
import hashlib
from typing import Dict, Optional, Tuple
from .user_manager import UserManager
from .session_manager import SessionManager

logger = logging.getLogger(__name__)

class Authentication:
    def __init__(self, 
                 users_file: str = "data/users.json",
                 sessions_file: str = "data/sessions.json",
                 session_timeout: int = 3600):
        
        try:
            self.user_manager = UserManager(users_file)
            self.session_manager = SessionManager(sessions_file, session_timeout)
        except Exception as e:
            logger.critical(f"Error crítico inicializando Authentication: {e}")
            raise
    
    def _sanitize_username_for_logs(self, username: str) -> str:
        if not username:
            return "unknown"
        return hashlib.sha256(username.encode()).hexdigest()[:16]
    
    def login(self, username: str, password: str, client_ip: str) -> Tuple[bool, str, Optional[str]]:
        sanitized_user = self._sanitize_username_for_logs(username)
        
        try:
            if not self.user_manager.user_exists(username):
                return False, "Credenciales inválidas", None
            
            user_info = self.user_manager.get_user_info(username)
            if not user_info or not user_info.get('is_active', True):
                return False, "Credenciales inválidas", None
            
            if not self.user_manager.authenticate_user(username, password):
                return False, "Credenciales inválidas", None
            
            session_id = self.session_manager.create_session(username, client_ip)
            if not session_id:
                return False, "Error interno del sistema", None
                
            return True, "Login exitoso", session_id
            
        except Exception as e:
            logger.error(f"Error en login para usuario [{sanitized_user}]: {e}")
            return False, "Error interno del sistema", None
    
    def validate_session(self, session_id: str, client_ip: str) -> Tuple[bool, Optional[str]]:
        try:
            if not session_id:
                return False, None
            
            if self.session_manager.validate_session(session_id, client_ip):
                username = self.session_manager.get_session_username(session_id)
                if username and self.user_manager.user_exists(username):
                    user_info = self.user_manager.get_user_info(username)
                    if user_info and user_info.get('is_active', True):
                        return True, username
                self.session_manager.destroy_session(session_id)
                
            return False, None
            
        except Exception as e:
            logger.error(f"Error validando sesión: {e}")
            return False, None
    
    def logout(self, session_id: str) -> bool:
        try:
            return self.session_manager.destroy_session(session_id)
        except Exception as e:
            logger.error(f"Error en logout: {e}")
            return False
    
    def logout_user(self, username: str) -> int:
        sanitized_user = self._sanitize_username_for_logs(username)
        
        try:
            result = self.session_manager.destroy_user_sessions(username)
            if result > 0:
                logger.info(f"Cerradas {result} sesiones para usuario [{sanitized_user}]")
            return result
        except Exception as e:
            logger.error(f"Error cerrando sesiones de usuario [{sanitized_user}]: {e}")
            return 0
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        sanitized_user = self._sanitize_username_for_logs(username)
        
        try:
            if not self.user_manager.authenticate_user(username, old_password):
                return False, "Contraseña actual incorrecta"
            
            if not self.user_manager.update_user_password(username, new_password):
                return False, "Error cambiando contraseña"
            
            sessions_closed = self.logout_user(username)
            if sessions_closed == 0:
                logger.warning(f"Contraseña cambiada para [{sanitized_user}] pero no se pudieron cerrar sesiones existentes")
                return True, "Contraseña cambiada, pero no se pudieron cerrar sesiones existentes"
            
            logger.info(f"Contraseña cambiada exitosamente para [{sanitized_user}], {sessions_closed} sesiones cerradas")
            return True, f"Contraseña cambiada exitosamente. {sessions_closed} sesiones cerradas"
            
        except ValueError as e:
            return False, str(e)
        except Exception as e:
            logger.error(f"Error cambiando contraseña para [{sanitized_user}]: {e}")
            return False, "Error interno cambiando contraseña"
    
    def create_user(self, username: str, password: str, is_active: bool = True) -> Tuple[bool, str]:
        sanitized_user = self._sanitize_username_for_logs(username)
        
        try:
            if self.user_manager.add_user(username, password, is_active):
                logger.info(f"Usuario [{sanitized_user}] creado exitosamente")
                return True, f"Usuario {username} creado exitosamente"
            return False, f"El usuario {username} ya existe"
        except ValueError as e:
            return False, str(e)
        except Exception as e:
            logger.error(f"Error creando usuario [{sanitized_user}]: {e}")
            return False, f"Error interno creando usuario"
    
    def deactivate_user(self, username: str) -> Tuple[bool, str]:
        sanitized_user = self._sanitize_username_for_logs(username)
        
        try:
            if not self.user_manager.user_exists(username):
                return False, "Usuario no encontrado"
                
            if not self.user_manager.deactivate_user(username):
                return False, "Error desactivando usuario"
                
            sessions_closed = self.logout_user(username)
            logger.info(f"Usuario [{sanitized_user}] desactivado, {sessions_closed} sesiones cerradas")
            return True, f"Usuario desactivado. {sessions_closed} sesiones cerradas"
            
        except Exception as e:
            logger.error(f"Error desactivando usuario [{sanitized_user}]: {e}")
            return False, "Error interno desactivando usuario"
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        try:
            if not self.user_manager.user_exists(username):
                return None
            
            users_list = self.user_manager.list_users()
            for user_info in users_list:
                if user_info['username'] == username:
                    return user_info
            return None
        except Exception as e:
            sanitized_user = self._sanitize_username_for_logs(username)
            logger.error(f"Error obteniendo info de usuario [{sanitized_user}]: {e}")
            return None
    
    def get_active_sessions(self):
        try:
            return self.session_manager.get_active_sessions()
        except Exception as e:
            logger.error(f"Error obteniendo sesiones activas: {e}")
            return []
    
    def get_user_statistics(self) -> Dict:
        try:
            return {
                'total_users': self.user_manager.get_user_count(),
                'active_sessions': self.session_manager.get_session_count(),
                'all_users': self.user_manager.list_users()
            }
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return {
                'total_users': 0,
                'active_sessions': 0,
                'all_users': []
            }
    
    def cleanup_expired_sessions(self):
        try:
            self.session_manager.get_active_sessions()
        except Exception as e:
            logger.error(f"Error limpiando sesiones expiradas: {e}")