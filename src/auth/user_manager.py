import json
import os
import hashlib
import secrets
import tempfile
import stat
import fcntl
from typing import Dict, Optional, List, Tuple
from datetime import datetime

class UserManager:
    def __init__(self, users_file: str = "data/users.json"):
        self.users_file = users_file
        self._lock_file = users_file + ".lock"
        self.users = self._load_users()
    
    def _load_users(self) -> Dict[str, dict]:
        try:
            if not os.path.exists(self.users_file):
                return {}
            
            with open(self.users_file, 'r', encoding='utf-8') as f:
                return json.load(f)
                
        except Exception as e:
            print(f"Error cargando usuarios: {e}")
            if isinstance(e, json.JSONDecodeError):
                try:
                    if os.path.exists(self.users_file):
                        backup_file = f"{self.users_file}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        os.rename(self.users_file, backup_file)
                        print(f"Archivo corrupto respaldado como: {backup_file}")
                except Exception as backup_error:
                    print(f"Error creando backup: {backup_error}")
            
            return {}
    
    def _acquire_lock(self) -> bool:
        try:
            self._lock_fd = open(self._lock_file, 'w')
            fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_EX)
            return True
        except (IOError, OSError, ImportError):
            try:
                import msvcrt
                self._lock_fd = open(self._lock_file, 'w')
                msvcrt.locking(self._lock_fd.fileno(), msvcrt.LK_NBLCK, 1)
                return True
            except (ImportError, OSError):
                self._lock_fd = None
                return True
        except Exception:
            self._lock_fd = None
            return True
    
    def _release_lock(self):
        try:
            if hasattr(self, '_lock_fd') and self._lock_fd:
                try:
                    fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_UN)
                except (AttributeError, IOError):
                    try:
                        import msvcrt
                        msvcrt.locking(self._lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
                    except (ImportError, AttributeError):
                        pass
                self._lock_fd.close()
                try:
                    os.unlink(self._lock_file)
                except OSError:
                    pass
        except Exception:
            pass
    
    def _save_users(self, users_data: Dict[str, dict] = None) -> bool:
        data_to_save = users_data or self.users
        temp_filename = None
        
        if not self._acquire_lock():
            return False
        
        try:
            dir_path = os.path.dirname(self.users_file)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            
            temp_dir = dir_path if dir_path else os.path.dirname(os.path.abspath(self.users_file))
            with tempfile.NamedTemporaryFile(
                mode='w', 
                encoding='utf-8', 
                dir=temp_dir,
                delete=False
            ) as tmp_file:
                json.dump(data_to_save, tmp_file, indent=2, ensure_ascii=False)
                temp_filename = tmp_file.name
            
            try:
                os.chmod(temp_filename, stat.S_IRUSR | stat.S_IWUSR)
            except (OSError, NotImplementedError):
                pass
            
            os.replace(temp_filename, self.users_file)
            temp_filename = None
            return True
            
        except Exception as e:
            print(f"Error guardando usuarios: {e}")
            return False
            
        finally:
            if temp_filename and os.path.exists(temp_filename):
                try:
                    os.unlink(temp_filename)
                except OSError:
                    pass
            self._release_lock()
    
    def _hash_password(self, password: str) -> str:
        salt = secrets.token_bytes(32)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return salt.hex() + ':' + key.hex()
    
    def _verify_password(self, stored_hash: str, password: str) -> bool:
        try:
            salt_hex, key_hex = stored_hash.split(':', 1)
            salt = bytes.fromhex(salt_hex)
            stored_key = bytes.fromhex(key_hex)
            
            new_key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000
            )
            return secrets.compare_digest(new_key, stored_key)
        except (ValueError, AttributeError):
            return False
    
    def _validate_username(self, username: str) -> bool:
        if not username or not isinstance(username, str):
            return False
        
        forbidden_chars = ['/', '\\', '..', ':', '"', "'", '<', '>', '|']
        if any(char in username for char in forbidden_chars):
            return False
        
        if len(username) < 1 or len(username) > 50:
            return False
        
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        if not self._validate_username(username):
            return False
            
        if username not in self.users:
            return False
        
        user_data = self.users[username]
        if not user_data.get('is_active', True):
            return False
        
        if self._verify_password(user_data['password_hash'], password):
            user_data['last_login'] = datetime.now().isoformat()
            self._save_users()
            return True
        
        return False
    
    def user_exists(self, username: str) -> bool:
        return username in self.users
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        if username not in self.users:
            return None
        
        user_data = self.users[username]
        return {
            'username': username,
            'created_at': user_data.get('created_at', 'Unknown'),
            'last_login': user_data.get('last_login', 'Never'),
            'is_active': user_data.get('is_active', True)
        }
    
    def add_user(self, username: str, password: str, is_active: bool = True) -> bool:
        if not self._validate_username(username):
            raise ValueError("Nombre de usuario inválido")
            
        if self.user_exists(username):
            return False
        
        if len(password) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres")
        
        self.users[username] = {
            "password_hash": self._hash_password(password),
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "is_active": is_active
        }
        
        return self._save_users()
    
    def update_user_password(self, username: str, new_password: str) -> bool:
        if not self.user_exists(username):
            return False
        
        if len(new_password) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres")
        
        self.users[username]['password_hash'] = self._hash_password(new_password)
        return self._save_users()
    
    def deactivate_user(self, username: str) -> bool:
        if not self.user_exists(username):
            return False
        
        self.users[username]['is_active'] = False
        return self._save_users()
    
    def activate_user(self, username: str) -> bool:
        if not self.user_exists(username):
            return False
        
        self.users[username]['is_active'] = True
        return self._save_users()
    
    def delete_user(self, username: str) -> bool:
        if not self.user_exists(username):
            return False
        
        del self.users[username]
        return self._save_users()
    
    def list_users(self) -> List[Dict[str, str]]:
        users_list = []
        for username, data in self.users.items():
            users_list.append({
                'username': username,
                'created_at': data.get('created_at', 'Unknown'),
                'last_login': data.get('last_login', 'Never'),
                'is_active': data.get('is_active', True)
            })
        return users_list
    
    def get_user_count(self) -> int:
        return len(self.users)
    
    def validate_credentials(self, username: str, password: str) -> Tuple[bool, str]:
        if not username or not password:
            return False, "Usuario y contraseña requeridos"
        
        if not self._validate_username(username):
            return False, "Nombre de usuario inválido"
        
        if not self.user_exists(username):
            return False, "Usuario no encontrado"
        
        if not self.users[username].get('is_active', True):
            return False, "Usuario desactivado"
        
        if not self.authenticate_user(username, password):
            return False, "Contraseña incorrecta"
        
        return True, "Autenticación exitosa"
    
    def initialize_admin_user(self, username: str = "admin", password: str = None) -> bool:
        if self.users:
            return False
        
        if not password:
            password = secrets.token_urlsafe(16)
            print(f"Usuario administrador creado:")
            print(f"Usuario: {username}")
            print(f"Contraseña: {password}")
            print("¡Guarde esta contraseña de forma segura!")
        
        return self.add_user(username, password, True)