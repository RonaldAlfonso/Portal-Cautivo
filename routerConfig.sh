
WAN_IF="enp0s31f6"
LAN_IF="wlp4s0"
HTTP_REDIRECT_PORT="8443"

BACKUP_DIR="/tmp/captive-router"
IPTABLES_BACKUP="$BACKUP_DIR/iptables.backup"
SYSCTL_BACKUP="$BACKUP_DIR/ip_forward"
start_router() {
    echo "Activando modo portal..."
    mkdir -p "$BACKUP_DIR"
    [[ -f "$IPTABLES_BACKUP" ]] || iptables-save >"$IPTABLES_BACKUP"
    [[ -f "$SYSCTL_BACKUP" ]] || cat /proc/sys/net/ipv4/ip_forward >"$SYSCTL_BACKUP"

    sysctl -w net.ipv4.ip_forward=1 >/dev/null #activa envio de paquetes entre interfaces
    iptables -F         # limpia la table filter
    iptables -t nat -F  # limpia la tabla de nateo
    iptables -t mangle -F #limpia la tabla de mangle
    iptables -X            #limpia las cadenas
    iptables -P INPUT ACCEPT #acepta entrada
    iptables -P OUTPUT ACCEPT #acepta salida
    iptables -P FORWARD DROP    #no acepta que pase de una interfaz a otra
    iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -p udp --dport 53 -j ACCEPT # acepta que pasen las consultas udp al puerto 53 dns  
    iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -p tcp --dport 53 -j ACCEPT #acepta que pasen las consultas tcp al puerto 53 dns
    iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE #nateo
    iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 
    iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT # esta y la de arriba permite que pasen las cosas de una conexion permitida
    iptables -t nat -A PREROUTING -i "$LAN_IF" -p tcp --dport 443 -j REDIRECT --to-port "$HTTP_REDIRECT_PORT"
   

   
    echo "Portal cautivo activo en https://10.42.0.1:${HTTPS_PORT}/login"
}

stop_router() {
    echo "Restaurando configuración..."
    if [[ -f "$IPTABLES_BACKUP" ]]; then
        iptables-restore <"$IPTABLES_BACKUP"
        rm -f "$IPTABLES_BACKUP"
    fi
    if [[ -f "$SYSCTL_BACKUP" ]]; then
        sysctl -w net.ipv4.ip_forward="$(cat "$SYSCTL_BACKUP")" >/dev/null
        rm -f "$SYSCTL_BACKUP"
    fi
    rmdir "$BACKUP_DIR" 2>/dev/null || true
    echo "Portal cautivo detenido."
}


case "$1" in
    start)
        start_router
        ;;
    stop)
        stop_router
        ;;
    *)
        echo "Uso: $0 {start|stop}"
        exit 1
        ;;
esac