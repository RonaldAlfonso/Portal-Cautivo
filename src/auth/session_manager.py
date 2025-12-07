import json
import os
import time
import secrets
import tempfile
import stat
import fcntl
from typing import Dict, Optional, List
from datetime import datetime
from src.server.ConexionManager import *

class SessionManager:
    def __init__(self, sessions_file: str = "data/sessions.json", session_timeout: int = 40):
        self.sessions_file = sessions_file
        self._lock_file = sessions_file + ".lock"
        self.session_timeout = session_timeout
        self._lock_fd = None
        self._locking_method = None
        self.sessions = self._load_sessions()
        self._cleanup_expired_sessions()
    
    def _load_sessions(self) -> Dict[str, dict]:
        if not self._acquire_lock(shared=True):
            return self._unsafe_load_sessions()
        
        try:
            return self._unsafe_load_sessions()
        finally:
            self._release_lock()
    
    def _unsafe_load_sessions(self) -> Dict[str, dict]:
        try:
            if not os.path.exists(self.sessions_file):
                return {}
            
            with open(self.sessions_file, 'r', encoding='utf-8') as f:
                sessions_data = json.load(f)
                
            processed_sessions = {}
            for session_id, session_data in sessions_data.items():
                try:
                    processed_data = session_data.copy()
                    timestamp_fields = ['created_at', 'last_activity', 'expires_at']
                    for field in timestamp_fields:
                        if field in processed_data:
                            if isinstance(processed_data[field], str):
                                processed_data[field] = float(processed_data[field])
                            elif not isinstance(processed_data[field], (int, float)):
                                processed_data[field] = time.time()
                    processed_sessions[session_id] = processed_data
                except (ValueError, TypeError):
                    continue
                    
            return processed_sessions
            
        except Exception as e:
            print(f"Error cargando sesiones: {e}")
            return {}
    
    def _acquire_lock(self, shared: bool = False) -> bool:
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                self._lock_fd = open(self._lock_file, 'w')
                
                try:
                    lock_type = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
                    fcntl.flock(self._lock_fd.fileno(), lock_type | fcntl.LOCK_NB)
                    self._locking_method = 'fcntl'
                    return True
                except (IOError, OSError, AttributeError):
                    pass
                
                try:
                    import msvcrt
                    lock_size = 1
                    msvcrt.locking(self._lock_fd.fileno(), msvcrt.LK_NBLCK if not shared else msvcrt.LK_NBRLCK, lock_size)
                    self._locking_method = 'msvcrt'
                    return True
                except (ImportError, OSError, AttributeError):
                    pass
                
                self._lock_fd.close()
                self._lock_fd = None
                self._locking_method = None
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    
            except Exception:
                if self._lock_fd:
                    try:
                        self._lock_fd.close()
                    except:
                        pass
                    self._lock_fd = None
                    self._locking_method = None
        
        return False
    
    def _release_lock(self):
        if not self._lock_fd:
            return
            
        try:
            if self._locking_method == 'fcntl':
                fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_UN)
            elif self._locking_method == 'msvcrt':
                import msvcrt
                msvcrt.locking(self._lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
            
            self._lock_fd.close()
        except Exception:
            try:
                self._lock_fd.close()
            except:
                pass
        finally:
            self._lock_fd = None
            self._locking_method = None
    
    def _save_sessions(self) -> bool:
        if not self._acquire_lock(shared=False):
            return False
        
        temp_filename = None
        
        try:
            dir_path = os.path.dirname(self.sessions_file)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            
            temp_dir = dir_path if dir_path else os.path.dirname(os.path.abspath(self.sessions_file))
            with tempfile.NamedTemporaryFile(
                mode='w', 
                encoding='utf-8', 
                dir=temp_dir,
                delete=False
            ) as tmp_file:
                sessions_to_save = {}
                for session_id, session_data in self.sessions.items():
                    sessions_to_save[session_id] = session_data.copy()
                    for key in ['created_at', 'last_activity', 'expires_at']:
                        if key in sessions_to_save[session_id]:
                            sessions_to_save[session_id][key] = str(sessions_to_save[session_id][key])
                
                json.dump(sessions_to_save, tmp_file, indent=2, ensure_ascii=False)
                temp_filename = tmp_file.name
            
            try:
                os.chmod(temp_filename, stat.S_IRUSR | stat.S_IWUSR)
            except (OSError, NotImplementedError):
                pass
            
            os.replace(temp_filename, self.sessions_file)
            temp_filename = None
            return True
            
        except Exception as e:
            print(f"Error guardando sesiones: {e}")
            return False
            
        finally:
            if temp_filename and os.path.exists(temp_filename):
                try:
                    os.unlink(temp_filename)
                except OSError:
                    pass
            self._release_lock()
    
    def _generate_session_id(self) -> str:
        for _ in range(10):
            session_id = secrets.token_urlsafe(32)
            if session_id not in self.sessions:
                return session_id
        return secrets.token_urlsafe(64)
    
    def _cleanup_expired_sessions(self, save_after_cleanup: bool = True):
       
        current_time = time.time()
        expired_sessions = [
        (session_id, session_data)
        for session_id, session_data in self.sessions.items()
        if current_time > session_data.get('expires_at', 0)]           

        for (session_id,session_data) in expired_sessions:
            ip=session_data.get('client_ip')
            mac=session_data.get('client_mac')

            if Conexion_Manager.ping(ip):
                session_data["expires_at"] = current_time + 3600
                print(f"[+] Sesión {session_id} renovada (IP activa: {ip})")

            else:    
                print("no entre a ping")
                Conexion_Manager.bloquear_usuario(ip,mac)
                del self.sessions[session_id]
        
        if expired_sessions and save_after_cleanup:
            self._save_sessions()
    
    def create_session(self, username: str, client_ip: str, mac: str = None) -> str:
        session_id = self._generate_session_id()
        current_time = time.time()
        
        session_data = {
            'username': username,
            'client_ip': client_ip,
            'created_at': current_time,
            'last_activity': current_time,
            'expires_at': current_time + self.session_timeout
        }
        
        if mac:
            session_data['client_mac'] = mac
        
        self.sessions[session_id] = session_data
        
        self._save_sessions()
        return session_id
    
    def validate_session(self, session_id: str, client_ip: str) -> bool:
        if session_id not in self.sessions:
            return False
        
        session_data = self.sessions[session_id]
        current_time = time.time()
        
        if current_time > session_data['expires_at']:
            del self.sessions[session_id]
            self._save_sessions()
            return False
        
        if session_data['client_ip'] != client_ip:
            return False
        
        session_data['last_activity'] = current_time
        session_data['expires_at'] = current_time + self.session_timeout
        self._save_sessions()
        
        return True
    
    def get_session_username(self, session_id: str) -> Optional[str]:
        if session_id in self.sessions:
            return self.sessions[session_id].get('username')
        return None
    
    def destroy_session(self, session_id: str) -> bool:
        if session_id in self.sessions:
            del self.sessions[session_id]
            return self._save_sessions()
        return False
    
    def destroy_user_sessions(self, username: str) -> int:
        sessions_to_remove = [
            session_id for session_id, session_data in self.sessions.items()
            if session_data.get('username') == username
        ]
        
        for session_id in sessions_to_remove:
            del self.sessions[session_id]
        
        if sessions_to_remove:
            self._save_sessions()
        
        return len(sessions_to_remove)
    
    def get_active_sessions(self) -> List[Dict]:
        self._cleanup_expired_sessions()
        
        active_sessions = []
        for session_id, session_data in self.sessions.items():
            active_sessions.append({
                'session_id': session_id,
                'username': session_data.get('username'),
                'client_ip': session_data.get('client_ip'),
                'created_at': datetime.fromtimestamp(session_data.get('created_at', 0)),
                'last_activity': datetime.fromtimestamp(session_data.get('last_activity', 0)),
                'expires_at': datetime.fromtimestamp(session_data.get('expires_at', 0))
            })
        
        return active_sessions
    
    def get_session_count(self) -> int:
        self._cleanup_expired_sessions()
        return len(self.sessions)
    
    def set_session_timeout(self, timeout_seconds: int):
        self.session_timeout = timeout_seconds
    
    def cleanup_all_sessions(self) -> int:
        session_count = len(self.sessions)
        self.sessions.clear()
        self._save_sessions()
        return session_count