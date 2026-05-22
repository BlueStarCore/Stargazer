#!/bin/bash
# Web UI Troubleshooting Script

echo "=== 1. Check webd daemon status ==="
if pgrep -f stargazer-webd >/dev/null; then
    echo "✓ webd is running (PID: $(pgrep -f stargazer-webd))"
else
    echo "✗ webd is NOT running!"
    echo "  Start it: /etc/init.d/stargazer-webd start"
fi

echo -e "\n=== 2. Check webd listeners ==="
netstat -tlnp 2>/dev/null | grep -E ":80|:443" || echo "No HTTP/HTTPS listeners found"

echo -e "\n=== 3. Check interface configuration ==="
echo "Querying mgmtd for system_interface config..."
/sbin/stargazer-ipc-cli list system_interface 2>/dev/null | while read iface; do
    echo -e "\nInterface: $iface"
    /sbin/stargazer-ipc-cli get system_interface "$iface" 2>/dev/null | grep -E "ip=|allowaccess="
done

echo -e "\n=== 4. Check iptables INPUT chain ==="
iptables -L INPUT -n -v | grep -E "Chain INPUT|sg_allow_|tcp dpt:80|tcp dpt:443" | head -20

echo -e "\n=== 5. Check webd logs ==="
dmesg | grep -i webd | tail -10 2>/dev/null || echo "No webd logs in dmesg"

echo -e "\n=== 6. Test local HTTP access ==="
if command -v wget >/dev/null 2>&1; then
    for ip in $(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}'); do
        echo "Testing http://$ip:80 ..."
        timeout 2 wget -q -O- http://$ip:80 >/dev/null 2>&1 && \
            echo "  ✓ http://$ip:80 responds" || \
            echo "  ✗ http://$ip:80 timeout/failed"
    done
else
    echo "wget not available, skipping HTTP test"
fi

echo -e "\n=== Recommended Actions ==="
echo "1. Ensure webd is running: ps aux | grep webd"
echo "2. Check interface has IP and allowaccess http:"
echo "   stargazer-cli> config system interface"
echo "   stargazer-cli(interface:eth0)> set allowaccess http ssh"
echo "   stargazer-cli(interface:eth0)> end"
echo "3. Verify iptables allows port 80:"
echo "   iptables -L sg_allow_eth0 -n"
echo "4. From external PC: curl http://<FIREWALL_IP>:80"
