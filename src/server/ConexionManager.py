import subprocess

class Conexion_Manager:
    @staticmethod
    def permitir_usuario(ip):
        print(f"--- Autorizando IP: {ip} ---")
        try:
            # 1. TABLA NAT: Excepción crítica.
            # Insertamos una regla en la posición 1 de PREROUTING.
            # Dice: "Si viene de esta IP, ACEPTA el paquete inmediatamente (no hagas REDIRECT)".
            # Esto libera el puerto 80 y 443 para este usuario.
            cmd_nat = ["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-s", ip, "-j", "ACCEPT"]
            subprocess.run(cmd_nat, check=True)

            # 2. TABLA FILTER (FORWARD): Salida.
            # Permitimos que esta IP envíe paquetes a la WAN.
            cmd_fwd_out = ["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "ACCEPT"]
            subprocess.run(cmd_fwd_out, check=True)

            # 3. TABLA FILTER (FORWARD): Retorno (Opcional pero recomendado si falla conntrack).
            # A veces la regla de "ESTABLISHED" está muy abajo o falla. 
            # Esto asegura que la respuesta de Internet hacia la IP también pase.
            cmd_fwd_in = ["iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "ACCEPT"]
            subprocess.run(cmd_fwd_in, check=True)

            print(f"Reglas aplicadas correctamente para {ip}")

        except subprocess.CalledProcessError as e:
            print(f"ERROR CRÍTICO al aplicar iptables: {e}")


    @staticmethod
    def bloquear_usuario(ip):
        print(f"--- Bloqueando IP: {ip} ---")
        try:
            # Eliminamos regla NAT
            subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-s", ip, "-j", "ACCEPT"], check=False)
            
            # Eliminamos regla FORWARD salida
            subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "ACCEPT"], check=False)
            
            # Eliminamos regla FORWARD entrada
            subprocess.run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "ACCEPT"], check=False)
            
        except Exception as e:
            print(f"Error al limpiar reglas: {e}")