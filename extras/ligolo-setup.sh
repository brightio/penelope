#!/bin/bash
# Ligolo-ng Auto Setup Script for Penelope
# Usage: ./ligolo-setup.sh [start|stop|status]

INTERFACE="ligolo"
PORT=11601

setup_tun() {
    echo "[+] Setting up TUN interface..."
    sudo ip tuntap add user $(whoami) mode tun $INTERFACE 2>/dev/null
    sudo ip link set $INTERFACE up
    echo "[✓] TUN interface ready"
}

start_proxy() {
    echo "[+] Starting ligolo-ng proxy..."

    # Check if proxy binary exists
    if [ ! -f "./proxy" ]; then
        echo "[!] Proxy binary not found. Downloading..."
        wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
        tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
        rm ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
        chmod +x proxy
    fi

    # Setup TUN interface
    setup_tun

    # Start proxy in background
    nohup ./proxy -selfcert > ligolo-proxy.log 2>&1 &
    echo $! > ligolo-proxy.pid
    echo "[✓] Proxy started on port $PORT (PID: $(cat ligolo-proxy.pid))"
    echo "[i] Log: tail -f ligolo-proxy.log"
}

stop_proxy() {
    if [ -f ligolo-proxy.pid ]; then
        echo "[+] Stopping ligolo-ng proxy..."
        kill $(cat ligolo-proxy.pid) 2>/dev/null
        rm ligolo-proxy.pid
        echo "[✓] Proxy stopped"
    else
        echo "[!] Proxy not running"
    fi
}

add_routes() {
    echo "[+] Detected agent connection. Add routes manually:"
    echo "    In ligolo-ng proxy console:"
    echo "    1. Type: session"
    echo "    2. Select session number"
    echo "    3. Type: ifconfig"
    echo "    4. Copy the networks shown"
    echo ""
    echo "    Then in another terminal:"
    echo "    sudo ip route add <NETWORK> dev $INTERFACE"
    echo ""
    echo "    Example:"
    echo "    sudo ip route add 192.168.1.0/24 dev $INTERFACE"
    echo "    sudo ip route add 10.10.10.0/24 dev $INTERFACE"
}

status() {
    echo "[*] Ligolo-ng Status:"
    echo ""

    # Check TUN interface
    if ip link show $INTERFACE &>/dev/null; then
        echo "[✓] TUN interface: UP"
    else
        echo "[✗] TUN interface: DOWN"
    fi

    # Check proxy
    if [ -f ligolo-proxy.pid ] && kill -0 $(cat ligolo-proxy.pid) 2>/dev/null; then
        echo "[✓] Proxy: RUNNING (PID: $(cat ligolo-proxy.pid))"
    else
        echo "[✗] Proxy: NOT RUNNING"
    fi

    # Check routes
    echo ""
    echo "[*] Current routes via $INTERFACE:"
    ip route | grep $INTERFACE || echo "    (none)"

    # Check listening ports
    echo ""
    echo "[*] Listening on port $PORT:"
    ss -tlnp | grep :$PORT || echo "    (not listening)"
}

cleanup() {
    echo "[+] Cleaning up..."
    stop_proxy
    sudo ip link delete $INTERFACE 2>/dev/null
    sudo ip route flush dev $INTERFACE 2>/dev/null
    echo "[✓] Cleanup complete"
}

case "$1" in
    start)
        start_proxy
        add_routes
        ;;
    stop)
        stop_proxy
        ;;
    status)
        status
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Ligolo-ng Auto Setup for Penelope"
        echo ""
        echo "Usage: $0 {start|stop|status|cleanup}"
        echo ""
        echo "Commands:"
        echo "  start   - Setup TUN interface and start proxy"
        echo "  stop    - Stop proxy"
        echo "  status  - Show current status"
        echo "  cleanup - Remove all ligolo components"
        echo ""
        echo "Quick Start:"
        echo "  1. Run: $0 start"
        echo "  2. In Penelope: run ligolo"
        echo "  3. Add routes as shown in console"
        exit 1
        ;;
esac
