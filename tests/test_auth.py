import unittest
import os
import time
import tempfile
import shutil
import sys
import json

# Agregar el directorio src al path para importar los módulos
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from auth.user_manager import UserManager
from auth.session_manager import SessionManager
from auth.authentication import Authentication

class TestAuthenticationSystem(unittest.TestCase):
    
    def setUp(self):
        """Configuración antes de cada test - CONSISTENTE con la guía"""
        # Usar estructura de directorios como en la guía
        self.base_dir = tempfile.mkdtemp()
        self.data_dir = os.path.join(self.base_dir, "data")
        self.src_dir = os.path.join(self.base_dir, "src")
        self.auth_dir = os.path.join(self.src_dir, "auth")
        
        # Crear estructura de directorios completa
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.auth_dir, exist_ok=True)
        
        # Rutas de archivos según estructura de la guía
        self.users_file = os.path.join(self.data_dir, "users.json")
        self.sessions_file = os.path.join(self.data_dir, "sessions.json")
        
        # SOLUCIÓN: Usar SOLO Authentication para mantener consistencia
        self.auth = Authentication(self.users_file, self.sessions_file, session_timeout=60)
        
        # Para tests específicos de UserManager y SessionManager, obtener las instancias internas
        self.user_manager = self.auth.user_manager
        self.session_manager = self.auth.session_manager
        
        print(f"🔧 Test directory: {self.base_dir}")
    
    def tearDown(self):
        """Limpieza después de cada test - CON VERIFICACIÓN DE ARCHIVOS"""
        if os.path.exists(self.base_dir):
            # VERIFICAR QUÉ ARCHIVOS SE CREARON ANTES DE ELIMINAR
            users_exists = os.path.exists(self.users_file)
            sessions_exists = os.path.exists(self.sessions_file)
            
            if users_exists or sessions_exists:
                print(f"📁 Archivos creados durante el test:")
                if users_exists:
                    try:
                        with open(self.users_file, 'r') as f:
                            content = json.load(f)
                        print(f"   ✅ users.json: {len(content)} usuarios")
                    except:
                        print(f"   ❌ users.json: Formato inválido")
                if sessions_exists:
                    try:
                        with open(self.sessions_file, 'r') as f:
                            content = json.load(f)
                        print(f"   ✅ sessions.json: {len(content)} sesiones")
                    except:
                        print(f"   ❌ sessions.json: Formato inválido")
            
            shutil.rmtree(self.base_dir)
    
    def _verify_file_creation(self, file_path, description):
        """Verifica explícitamente que un archivo se creó y tiene contenido válido"""
        self.assertTrue(os.path.exists(file_path), 
                       f"❌ {description} no se creó en {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                content = json.load(f)
            self.assertIsInstance(content, (dict, list), 
                                f"❌ {description} no tiene formato JSON válido")
            return content
        except json.JSONDecodeError as e:
            self.fail(f"❌ {description} tiene JSON corrupto: {e}")
    
    def test_00_directory_structure(self):
        """Verificar que la estructura de directorios es correcta según la guía"""
        self.assertTrue(os.path.exists(self.data_dir))
        self.assertTrue(os.path.exists(self.src_dir))
        self.assertTrue(os.path.exists(self.auth_dir))
        
        # Los archivos de datos deben estar en data/
        self.assertTrue(self.users_file.startswith(self.data_dir))
        self.assertTrue(self.sessions_file.startswith(self.data_dir))
    
    def test_01_user_creation(self):
        """Test creación de usuarios"""
        # Usuario válido
        result = self.user_manager.add_user("testuser", "password123", True)
        self.assertTrue(result)
        self.assertTrue(self.user_manager.user_exists("testuser"))
        
        # VERIFICAR PERSISTENCIA: Archivo debe crearse automáticamente
        users_content = self._verify_file_creation(self.users_file, "users.json")
        self.assertIn("testuser", users_content)
        
        # Usuario duplicado
        result = self.user_manager.add_user("testuser", "password123", True)
        self.assertFalse(result)
        
        # Usuario con contraseña corta
        with self.assertRaises(ValueError):
            self.user_manager.add_user("shortpass", "123", True)
        
        # Usuario con nombre inválido
        with self.assertRaises(ValueError):
            self.user_manager.add_user("invalid/user", "password123", True)
    
    def test_02_user_authentication(self):
        """Test autenticación de usuarios"""
        self.user_manager.add_user("authuser", "mypassword", True)
        
        # VERIFICAR PERSISTENCIA: users.json debe existir
        self._verify_file_creation(self.users_file, "users.json")
        
        # Credenciales correctas
        result, message = self.user_manager.validate_credentials("authuser", "mypassword")
        self.assertTrue(result)
        self.assertEqual(message, "Autenticación exitosa")
        
        # Contraseña incorrecta
        result, message = self.user_manager.validate_credentials("authuser", "wrongpassword")
        self.assertFalse(result)
        self.assertEqual(message, "Contraseña incorrecta")
        
        # Usuario no existe
        result, message = self.user_manager.validate_credentials("nonexistent", "password")
        self.assertFalse(result)
        self.assertEqual(message, "Usuario no encontrado")
    
    def test_03_user_management(self):
        """Test gestión de usuarios (activar/desactivar)"""
        self.user_manager.add_user("manageuser", "password123", True)
        
        # VERIFICAR PERSISTENCIA INICIAL
        initial_users = self._verify_file_creation(self.users_file, "users.json")
        self.assertIn("manageuser", initial_users)
        
        # Desactivar usuario
        result = self.user_manager.deactivate_user("manageuser")
        self.assertTrue(result)
        
        # VERIFICAR PERSISTENCIA POST-DESACTIVACIÓN
        updated_users = self._verify_file_creation(self.users_file, "users.json")
        self.assertFalse(updated_users["manageuser"]["is_active"])
        
        user_info = self.user_manager.get_user_info("manageuser")
        self.assertFalse(user_info['is_active'])
        
        # Reactivar usuario
        result = self.user_manager.activate_user("manageuser")
        self.assertTrue(result)
        user_info = self.user_manager.get_user_info("manageuser")
        self.assertTrue(user_info['is_active'])
        
        # Eliminar usuario
        result = self.user_manager.delete_user("manageuser")
        self.assertTrue(result)
        self.assertFalse(self.user_manager.user_exists("manageuser"))
    
    def test_04_session_creation(self):
        """Test creación de sesiones"""
        session_id = self.session_manager.create_session("testuser", "192.168.1.100")
        self.assertIsNotNone(session_id)
        self.assertEqual(len(session_id), 43)
        
        # VERIFICAR PERSISTENCIA: sessions.json debe crearse automáticamente
        sessions_content = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertIn(session_id, sessions_content)
        
        # Verificar que la sesión se guardó
        sessions = self.session_manager.get_active_sessions()
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]['username'], "testuser")
        self.assertEqual(sessions[0]['client_ip'], "192.168.1.100")
    
    def test_05_session_validation(self):
        """Test validación de sesiones"""
        session_id = self.session_manager.create_session("testuser", "192.168.1.100")
        
        # VERIFICAR PERSISTENCIA INICIAL
        self._verify_file_creation(self.sessions_file, "sessions.json")
        
        # Validación correcta
        result = self.session_manager.validate_session(session_id, "192.168.1.100")
        self.assertTrue(result)
        
        # IP incorrecta
        result = self.session_manager.validate_session(session_id, "192.168.1.101")
        self.assertFalse(result)
        
        # Sesión no existe
        result = self.session_manager.validate_session("invalidsession", "192.168.1.100")
        self.assertFalse(result)
    
    def test_06_session_expiration(self):
        """Test expiración de sesiones"""
        # Configurar timeout muy corto para la prueba
        self.session_manager.set_session_timeout(1)
        session_id = self.session_manager.create_session("testuser", "192.168.1.100")
        
        # VERIFICAR PERSISTENCIA INICIAL
        initial_sessions = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertIn(session_id, initial_sessions)
        
        # Sesión debe ser válida inicialmente
        self.assertTrue(self.session_manager.validate_session(session_id, "192.168.1.100"))
        
        # Esperar a que expire
        time.sleep(1.1)
        
        # Sesión debe estar expirada
        result = self.session_manager.validate_session(session_id, "192.168.1.100")
        self.assertFalse(result)
        
        # Verificar que se limpió automáticamente
        sessions = self.session_manager.get_active_sessions()
        self.assertEqual(len(sessions), 0)
    
    def test_07_session_cleanup(self):
        """Test limpieza de sesiones"""
        # Crear múltiples sesiones
        self.session_manager.create_session("user1", "192.168.1.100")
        self.session_manager.create_session("user2", "192.168.1.101")
        
        # VERIFICAR PERSISTENCIA INICIAL
        initial_sessions = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertEqual(len(initial_sessions), 2)
        
        # Verificar que existen
        self.assertEqual(self.session_manager.get_session_count(), 2)
        
        # Limpiar todas las sesiones
        count = self.session_manager.cleanup_all_sessions()
        self.assertEqual(count, 2)
        self.assertEqual(self.session_manager.get_session_count(), 0)
        
        # VERIFICAR PERSISTENCIA POST-LIMPIEZA
        final_sessions = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertEqual(len(final_sessions), 0)
    
    def test_08_auth_login(self):
        """Test sistema de autenticación completo - login"""
        # CORRECCIÓN: Usar auth.create_user en lugar de user_manager.add_user
        success, message = self.auth.create_user("authuser", "password123", True)
        self.assertTrue(success, message)
        
        # VERIFICAR PERSISTENCIA DE USUARIO
        users_content = self._verify_file_creation(self.users_file, "users.json")
        self.assertIn("authuser", users_content)
        
        # Login exitoso
        success, message, session_id = self.auth.login("authuser", "password123", "192.168.1.100")
        self.assertTrue(success, message)
        self.assertEqual(message, "Login exitoso")
        self.assertIsNotNone(session_id)
        
        # VERIFICAR PERSISTENCIA DE SESIÓN
        sessions_content = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertIn(session_id, sessions_content)
        
        # Login con credenciales incorrectas
        success, message, session_id = self.auth.login("authuser", "wrongpassword", "192.168.1.100")
        self.assertFalse(success)
        self.assertEqual(message, "Credenciales inválidas")
        self.assertIsNone(session_id)
        
        # Login con usuario desactivado
        success, message = self.auth.deactivate_user("authuser")
        self.assertTrue(success, message)
        success, message, session_id = self.auth.login("authuser", "password123", "192.168.1.100")
        self.assertFalse(success)
        self.assertEqual(message, "Credenciales inválidas")
    
    def test_09_auth_session_validation(self):
        """Test validación de sesiones en Authentication"""
        # CORRECCIÓN: Usar auth.create_user
        success, message = self.auth.create_user("sessionuser", "password123", True)
        self.assertTrue(success, message)
        
        success, message, session_id = self.auth.login("sessionuser", "password123", "192.168.1.100")
        self.assertTrue(success, message)
        
        # VERIFICAR PERSISTENCIA
        self._verify_file_creation(self.users_file, "users.json")
        self._verify_file_creation(self.sessions_file, "sessions.json")
        
        # Validar sesión correcta
        valid, username = self.auth.validate_session(session_id, "192.168.1.100")
        self.assertTrue(valid)
        self.assertEqual(username, "sessionuser")
        
        # Validar sesión con IP incorrecta
        valid, username = self.auth.validate_session(session_id, "192.168.1.101")
        self.assertFalse(valid)
        self.assertIsNone(username)
        
        # Validar sesión inexistente
        valid, username = self.auth.validate_session("invalidsession", "192.168.1.100")
        self.assertFalse(valid)
        self.assertIsNone(username)
    
    def test_10_auth_logout(self):
        """Test logout del sistema"""
        # CORRECCIÓN: Usar auth.create_user
        success, message = self.auth.create_user("logoutuser", "password123", True)
        self.assertTrue(success, message)
        
        success, message, session_id = self.auth.login("logoutuser", "password123", "192.168.1.100")
        self.assertTrue(success, message)
        
        # VERIFICAR PERSISTENCIA ANTES DEL LOGOUT
        sessions_before = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertIn(session_id, sessions_before)
        
        # Logout exitoso
        result = self.auth.logout(session_id)
        self.assertTrue(result)
        
        # VERIFICAR PERSISTENCIA DESPUÉS DEL LOGOUT
        sessions_after = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertNotIn(session_id, sessions_after)
        
        # Verificar que la sesión ya no es válida
        valid, username = self.auth.validate_session(session_id, "192.168.1.100")
        self.assertFalse(valid)
    
    def test_11_auth_password_change(self):
        """Test cambio de contraseña"""
        # CORRECCIÓN: Usar auth.create_user
        success, message = self.auth.create_user("passuser", "oldpassword", True)
        self.assertTrue(success, message)
        
        success, message, session_id = self.auth.login("passuser", "oldpassword", "192.168.1.100")
        self.assertTrue(success, message)
        
        # Cambio exitoso
        success, message = self.auth.change_password("passuser", "oldpassword", "newpassword123")
        self.assertTrue(success, message)
        self.assertIn("Contraseña cambiada exitosamente", message)
        
        # VERIFICAR PERSISTENCIA: La nueva contraseña debe funcionar
        success, message, session_id = self.auth.login("passuser", "newpassword123", "192.168.1.100")
        self.assertTrue(success)
        
        # Verificar que la contraseña antigua ya no funciona
        success, message, session_id = self.auth.login("passuser", "oldpassword", "192.168.1.100")
        self.assertFalse(success)
        
        # Cambio con contraseña actual incorrecta
        success, message = self.auth.change_password("passuser", "wrongold", "newpassword")
        self.assertFalse(success)
        self.assertEqual(message, "Contraseña actual incorrecta")
    
    def test_12_auth_user_creation(self):
        """Test creación de usuarios desde Authentication"""
        # Creación exitosa
        success, message = self.auth.create_user("newuser", "password123", True)
        self.assertTrue(success)
        self.assertEqual(message, "Usuario newuser creado exitosamente")
        
        # VERIFICAR PERSISTENCIA
        users_content = self._verify_file_creation(self.users_file, "users.json")
        self.assertIn("newuser", users_content)
        
        # Usuario duplicado
        success, message = self.auth.create_user("newuser", "password123", True)
        self.assertFalse(success)
        self.assertEqual(message, "El usuario newuser ya existe")
        
        # Validación de contraseña corta
        success, message = self.auth.create_user("shortpass", "123", True)
        self.assertFalse(success)
        self.assertIn("al menos 8 caracteres", message)
    
    def test_13_auth_user_deactivation(self):
        """Test desactivación de usuarios desde Authentication"""
        # CORRECCIÓN: Usar auth.create_user
        success, message = self.auth.create_user("deactivateuser", "password123", True)
        self.assertTrue(success, message)
        
        success, message, session_id = self.auth.login("deactivateuser", "password123", "192.168.1.100")
        self.assertTrue(success, message)
        
        # VERIFICAR PERSISTENCIA ANTES DE DESACTIVAR
        sessions_before = self._verify_file_creation(self.sessions_file, "sessions.json")
        initial_session_count = len(sessions_before)
        
        # Desactivar usuario
        success, message = self.auth.deactivate_user("deactivateuser")
        self.assertTrue(success, message)
        self.assertIn("Usuario desactivado", message)
        
        # VERIFICAR PERSISTENCIA: El usuario debe estar desactivado en el archivo
        users_content = self._verify_file_creation(self.users_file, "users.json")
        self.assertFalse(users_content["deactivateuser"]["is_active"])
        
        # VERIFICAR PERSISTENCIA: Las sesiones deben eliminarse
        sessions_after = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertLess(len(sessions_after), initial_session_count)
        
        # Verificar que no puede iniciar sesión
        success, message, session_id = self.auth.login("deactivateuser", "password123", "192.168.1.100")
        self.assertFalse(success)
    
    def test_14_auth_statistics(self):
        """Test obtención de estadísticas"""
        # Estadísticas iniciales
        stats = self.auth.get_user_statistics()
        self.assertEqual(stats['total_users'], 0)
        self.assertEqual(stats['active_sessions'], 0)
        self.assertEqual(len(stats['all_users']), 0)
        
        # Agregar usuarios y sesiones
        self.auth.create_user("statuser1", "password123", True)
        self.auth.create_user("statuser2", "password123", True)
        self.auth.login("statuser1", "password123", "192.168.1.100")
        
        # VERIFICAR PERSISTENCIA
        self._verify_file_creation(self.users_file, "users.json")
        self._verify_file_creation(self.sessions_file, "sessions.json")
        
        stats = self.auth.get_user_statistics()
        self.assertEqual(stats['total_users'], 2)
        self.assertEqual(stats['active_sessions'], 1)
        self.assertEqual(len(stats['all_users']), 2)
    
    def test_15_concurrent_access(self):
        """Test acceso concurrente simulado"""
        self.auth.create_user("concurrentuser", "password123", True)
        
        # Simular múltiples logins desde la misma IP
        sessions = []
        for i in range(5):
            success, message, session_id = self.auth.login("concurrentuser", "password123", f"192.168.1.{i}")
            self.assertTrue(success)
            sessions.append(session_id)
        
        # VERIFICAR PERSISTENCIA: Todas las sesiones deben estar en el archivo
        sessions_content = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertEqual(len(sessions_content), 5)
        
        # Todas las sesiones deben ser válidas
        for i, session_id in enumerate(sessions):
            valid, username = self.auth.validate_session(session_id, f"192.168.1.{i}")
            self.assertTrue(valid)
            self.assertEqual(username, "concurrentuser")
    
    def test_16_file_persistence(self):
        """Test persistencia en archivos"""
        self.auth.create_user("persistuser", "password123", True)
        success, message, session_id = self.auth.login("persistuser", "password123", "192.168.1.100")
        
        # VERIFICAR PERSISTENCIA INICIAL
        initial_users = self._verify_file_creation(self.users_file, "users.json")
        initial_sessions = self._verify_file_creation(self.sessions_file, "sessions.json")
        
        # Crear nueva instancia para simular reinicio
        new_auth = Authentication(self.users_file, self.sessions_file, session_timeout=60)
        
        # Verificar que el usuario persiste
        user_info = new_auth.get_user_info("persistuser")
        self.assertIsNotNone(user_info)
        self.assertEqual(user_info['username'], "persistuser")
        
        # Verificar que la sesión persiste
        valid, username = new_auth.validate_session(session_id, "192.168.1.100")
        self.assertTrue(valid)
        self.assertEqual(username, "persistuser")
    
    def test_17_error_handling(self):
        """Test manejo de errores"""
        # Login con datos vacíos
        success, message, session_id = self.auth.login("", "", "192.168.1.100")
        self.assertFalse(success)
        
        # Validar sesión vacía
        valid, username = self.auth.validate_session("", "192.168.1.100")
        self.assertFalse(valid)
        
        # Logout de sesión inexistente
        result = self.auth.logout("invalidsession")
        self.assertFalse(result)
    
    def test_18_admin_initialization(self):
        """Test inicialización de usuario admin"""
        # Solo debe funcionar cuando no hay usuarios
        result = self.user_manager.initialize_admin_user("admin", "adminpassword123")
        self.assertTrue(result)
        self.assertTrue(self.user_manager.user_exists("admin"))
        
        # VERIFICAR PERSISTENCIA
        users_content = self._verify_file_creation(self.users_file, "users.json")
        self.assertIn("admin", users_content)
        
        # No debe funcionar si ya hay usuarios
        result = self.user_manager.initialize_admin_user("admin2", "password123")
        self.assertFalse(result)
    
    def test_19_files_created_automatically(self):
        """Verificar que los archivos se crean automáticamente"""
        # Los archivos no deben existir inicialmente
        self.assertFalse(os.path.exists(self.users_file))
        self.assertFalse(os.path.exists(self.sessions_file))
        
        # Al crear un usuario, users.json debe crearse automáticamente
        result = self.user_manager.add_user("testuser", "password123", True)
        self.assertTrue(result)
        
        # VERIFICAR EXPLÍCITAMENTE
        users_content = self._verify_file_creation(self.users_file, "users.json")
        self.assertIn("testuser", users_content)
        
        # Al crear una sesión, sessions.json debe crearse automáticamente
        session_id = self.session_manager.create_session("testuser", "192.168.1.100")
        self.assertIsNotNone(session_id)
        
        # VERIFICAR EXPLÍCITAMENTE
        sessions_content = self._verify_file_creation(self.sessions_file, "sessions.json")
        self.assertIn(session_id, sessions_content)
    
    def test_20_data_directory_creation(self):
        """Verificar que el directorio data se crea automáticamente si no existe"""
        # Eliminar directorio data
        if os.path.exists(self.data_dir):
            shutil.rmtree(self.data_dir)
        
        self.assertFalse(os.path.exists(self.data_dir))
        
        # Al crear usuario, debe crear automáticamente el directorio data
        result = self.user_manager.add_user("testuser", "password123", True)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.data_dir))
        
        # VERIFICAR QUE EL ARCHIVO TAMBIÉN SE CREÓ
        self._verify_file_creation(self.users_file, "users.json")
    
    def test_21_data_integrity_verification(self):
        """Test EXTRA: Verificación completa de integridad de datos"""
        # Crear usuario y sesión
        self.auth.create_user("integrityuser", "password123", True)
        success, message, session_id = self.auth.login("integrityuser", "password123", "192.168.1.100")
        self.assertTrue(success, message)
        
        # VERIFICAR ESTRUCTURA COMPLETA DE users.json
        users_content = self._verify_file_creation(self.users_file, "users.json")
        user_data = users_content["integrityuser"]
        
        required_user_fields = ["password_hash", "created_at", "last_login", "is_active"]
        for field in required_user_fields:
            self.assertIn(field, user_data, f"Campo {field} faltante en user data")
        
        # VERIFICAR ESTRUCTURA COMPLETA DE sessions.json
        sessions_content = self._verify_file_creation(self.sessions_file, "sessions.json")
        session_data = sessions_content[session_id]
        
        required_session_fields = ["username", "client_ip", "created_at", "last_activity", "expires_at"]
        for field in required_session_fields:
            self.assertIn(field, session_data, f"Campo {field} faltante en session data")

def run_tests():
    """Función para ejecutar todas las pruebas"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAuthenticationSystem)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print("🧪 RESUMEN COMPLETO DE PRUEBAS - PERSISTENCIA VERIFICADA")
    print(f"{'='*60}")
    print(f"Tests ejecutados: {result.testsRun}")
    print(f"✅ Éxitos: {result.testsRun - len(result.errors) - len(result.failures)}")
    print(f"❌ Errores: {len(result.errors)}")
    print(f"⚠️  Fallos: {len(result.failures)}")
    
    if result.wasSuccessful():
        print(f"\n🎉 ¡TODAS LAS {result.testsRun} PRUEBAS PASARON!")
        print("   ✅ Persistencia de archivos VERIFICADA")
        print("   ✅ Integridad de datos CONFIRMADA") 
        print("   ✅ Sistema listo para producción")
        return True
    else:
        print(f"\n🔧 {len(result.errors) + len(result.failures)} pruebas necesitan atención.")
        return False

if __name__ == '__main__':
    print("🧪 EJECUTANDO PRUEBAS COMPLETAS CON VERIFICACIÓN DE PERSISTENCIA")
    print("=" * 70)
    print("✅ Verificando CREACIÓN REAL de archivos JSON")
    print("✅ Validando INTEGRIDAD de datos persistidos") 
    print("✅ Comprobando CARGA CORRECTA tras reinicios")
    print("=" * 70)
    
    success = run_tests()
    
    if success:
        print("\n" + "🎯 PERSISTENCIA CONFIRMADA:".center(60))
        print("✅ Los módulos CREAN y MANTIENEN archivos correctamente")
        print("✅ Los datos se PERSISTEN y RECUPERAN exitosamente")
        print("✅ La estructura de archivos es ROBUSTA y CONFIABLE")
    else:
        print("\n⚠️  PROBLEMAS DE PERSISTENCIA DETECTADOS")
        print("   Revisa los logs de arriba para ver qué archivos se crearon.")