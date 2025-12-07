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
            cmd_fwd_out = ["iptables", "-A", "FORWARD", "-s", ip, "-m", "mac", "--mac-source", mac, "-j", "ACCEPT"]
            subprocess.run(cmd_fwd_out, check=True)

            subprocess.run([
            "iptables", "-A", "FORWARD", 
            "-d", ip, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT"
        ], check=True)

            print(f"Reglas aplicadas correctamente para {ip} / {mac}")

        except subprocess.CalledProcessError as e:
            print(f"ERROR CRÍTICO al aplicar iptables: {e}")


    @staticmethod
    def bloquear_usuario(ip, mac):
        print(f"--- Bloqueando IP: {ip} / MAC: {mac} ---")
        try:
           
            subprocess.run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-s", ip,
                "-m", "mac", "--mac-source", mac,
                "-j", "ACCEPT"
            ], check=False)

            # Eliminamos FORWARD salida (solo IP)
            subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-m", "mac", "--mac-source", "-j", "ACCEPT"], check=False)

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


    @staticmethod
    def ping(ip: str) -> bool:
        print("entre al meodo estatico de ping")
        if not ip:
            return False

        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except Exception:
            return False