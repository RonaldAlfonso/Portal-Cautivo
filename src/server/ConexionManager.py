import subprocess

class Conexion_Manager:
    @staticmethod
    def permitir_usuario(ip, mac):
        print(f"--- Autorizando IP: {ip} / MAC: {mac} ---")
        try:
            # 1. TABLA NAT: Excepción crítica con IP + MAC
            cmd_nat = [
                "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                "-s", ip,
                "-m", "mac", "--mac-source", mac,
                "-j", "ACCEPT"
            ]
            subprocess.run(cmd_nat, check=True)

            # 2. TABLA FILTER (FORWARD): Salida (solo IP)
            cmd_fwd_out = ["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "ACCEPT"]
            subprocess.run(cmd_fwd_out, check=True)

            # 3. TABLA FILTER (FORWARD): Retorno (solo IP)
            cmd_fwd_in = ["iptables", "-I", "FORWARD", "1", "-d", ip, "-j", "ACCEPT"]
            subprocess.run(cmd_fwd_in, check=True)

            print(f"Reglas aplicadas correctamente para {ip} / {mac}")

        except subprocess.CalledProcessError as e:
            print(f"ERROR CRÍTICO al aplicar iptables: {e}")


    @staticmethod
    def bloquear_usuario(ip, mac):
        print(f"--- Bloqueando IP: {ip} / MAC: {mac} ---")
        try:
            # Eliminamos regla NAT IP + MAC
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-s", ip,
                "-m", "mac", "--mac-source", mac,
                "-j", "ACCEPT"
            ], check=False)

            # Eliminamos FORWARD salida (solo IP)
            subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "ACCEPT"], check=False)

            # Eliminamos FORWARD entrada (solo IP)
            subprocess.run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "ACCEPT"], check=False)

        except Exception as e:
            print(f"Error al limpiar reglas: {e}")



    @staticmethod
    def get_mac(ip):
        try:
            # Ejecutar "arp -n IP"
            output = subprocess.check_output(["arp", "-n", ip]).decode()
            for line in output.split("\n"):
                if ip in line:
                    parts = line.split()
                    return parts[2]
        except:
            return None

        return None


