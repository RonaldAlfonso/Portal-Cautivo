from src.auth.authentication import *
import threading
import time
def start_cleanup_thread(autentication_manager:Authentication):
    def cleanup_loop():
        while True:
         
            try:
                
                autentication_manager.session_manager._cleanup_expired_sessions()
            except Exception as e:
                print(f"[CLEANUP ERROR] {e}")

            time.sleep(30)
    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()