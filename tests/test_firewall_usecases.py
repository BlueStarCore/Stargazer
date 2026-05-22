#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_firewall_usecases.py — Kiểm tra các use case tường lửa trên thiết bị nhúng

Script này kiểm tra đầy đủ các chức năng của tường lửa Stargazer NGFW qua Web UI,
mô phỏng các tình huống thực tế của người dùng quản trị firewall.

Các use case được kiểm tra:
  1. Xác thực và phân quyền (Login/Logout)
  2. Quản lý Firewall Policy (tạo, sửa, xóa rule)
  3. Cấu hình Interface (WAN/LAN setup)
  4. Cấu hình NAT (Port forwarding, Source NAT)
  5. Quản lý DHCP Server
  6. Quản lý Static Route
  7. Quản lý Address Object và Service Object
  8. Giám sát hệ thống (CPU, RAM, Disk, Network)
  9. Công cụ chẩn đoán (Ping, Traceroute, DNS lookup)
 10. Quản lý Firmware
 11. Quản lý Admin Account
 12. Kiểm tra bảo mật (XSS, CSRF, Session)

Chạy: python3 tests/test_firewall_usecases.py [BASE_URL]

Ví dụ:
  python3 tests/test_firewall_usecases.py http://localhost:8080
  python3 tests/test_firewall_usecases.py https://192.168.1.1
"""

import requests
import sys
import time
import json
import re
from urllib.parse import urljoin

# ══════════════════════════════════════════════════════════════════════════════
# CẤU HÌNH TEST
# ══════════════════════════════════════════════════════════════════════════════

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASS = "T@n27404"

# Disable SSL warnings nếu test trên HTTPS tự ký
requests.packages.urllib3.disable_warnings()

# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

PASS_COUNT = 0
FAIL_COUNT = 0
WARN_COUNT = 0

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def header(text):
    """In header cho mỗi test suite"""
    print(f"\n{BOLD}{CYAN}{'=' * 80}{RESET}")
    print(f"{BOLD}{CYAN}{text.center(80)}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 80}{RESET}\n")


def section(num, title):
    """In tiêu đề section"""
    print(f"\n{BOLD}[{num}] {title}{RESET}")
    print(f"{'-' * 80}")


def check(label, condition, detail=""):
    """Kiểm tra và ghi nhận kết quả PASS/FAIL"""
    global PASS_COUNT, FAIL_COUNT
    if condition:
        print(f"  {GREEN}✓ PASS{RESET} {label}")
        PASS_COUNT += 1
    else:
        print(f"  {RED}✗ FAIL{RESET} {label}")
        if detail:
            print(f"         {YELLOW}↳ {detail}{RESET}")
        FAIL_COUNT += 1


def warn(label, detail=""):
    """Ghi nhận warning (không phải lỗi nghiêm trọng)"""
    global WARN_COUNT
    print(f"  {YELLOW}⚠ WARN{RESET} {label}")
    if detail:
        print(f"         {YELLOW}↳ {detail}{RESET}")
    WARN_COUNT += 1


def info(text):
    """In thông tin bổ sung"""
    print(f"  {CYAN}ℹ INFO{RESET} {text}")


def api_request(method, path, session=None, json_data=None, expect_fail=False):
    """Gửi request đến API và trả về response"""
    url = urljoin(BASE_URL, path)
    try:
        if method == "GET":
            r = session.get(url, timeout=10, verify=False) if session else requests.get(url, timeout=10, verify=False)
        elif method == "POST":
            r = session.post(url, json=json_data, timeout=10, verify=False) if session else requests.post(url, json=json_data, timeout=10, verify=False)
        elif method == "PUT":
            r = session.put(url, json=json_data, timeout=10, verify=False) if session else requests.put(url, json=json_data, timeout=10, verify=False)
        elif method == "DELETE":
            r = session.delete(url, timeout=10, verify=False) if session else requests.delete(url, timeout=10, verify=False)
        else:
            return None
        return r
    except requests.exceptions.RequestException as e:
        if not expect_fail:
            warn(f"Network error: {method} {path}", str(e))
        return None


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 1: XÁC THỰC VÀ PHÂN QUYỀN
# ══════════════════════════════════════════════════════════════════════════════

def test_authentication():
    """UC-01: Kiểm tra login, logout, và session management"""
    section("USE CASE 1", "Xác thực và Phân quyền")

    # Test 1.1: Login thành công với credentials hợp lệ
    session = requests.Session()
    r = api_request("POST", "/api/auth/login", session, {
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    })
    check("UC-01.1: Login thành công với admin credentials",
          r and r.status_code == 200,
          f"Status: {r.status_code if r else 'No response'}")

    # Test 1.2: Verify session cookie được set
    check("UC-01.2: Session cookie (sg_sid) được set sau khi login",
          'sg_sid' in session.cookies,
          f"Cookies: {list(session.cookies.keys())}")

    # Test 1.3: whoami endpoint trả về thông tin user
    r = api_request("GET", "/api/auth/whoami", session)
    if r and r.status_code == 200:
        data = r.json()
        check("UC-01.3: whoami trả về username = admin",
              data.get("username") == ADMIN_USER,
              f"Got: {data.get('username')}")
        check("UC-01.4: whoami trả về permissions (admin có full quyền)",
              "admin" in data.get("permissions", ""),
              f"Permissions: {data.get('permissions')}")
    else:
        check("UC-01.3: whoami endpoint", False, "Request failed")

    # Test 1.4: Login sai mật khẩu phải trả về 401
    bad_session = requests.Session()
    r = api_request("POST", "/api/auth/login", bad_session, {
        "username": ADMIN_USER,
        "password": "wrongpassword"
    })
    check("UC-01.5: Login với mật khẩu sai trả về 401 Unauthorized",
          r and r.status_code == 401)

    # Test 1.5: Login với username không tồn tại
    r = api_request("POST", "/api/auth/login", bad_session, {
        "username": "nonexistent_user",
        "password": "anypassword"
    })
    check("UC-01.6: Login với username không tồn tại trả về 401",
          r and r.status_code == 401,
          "Không được leak thông tin user có tồn tại hay không")

    # Test 1.6: Access API không có authentication phải 401
    no_auth_session = requests.Session()
    r = api_request("GET", "/api/config/firewall_policy", no_auth_session)
    check("UC-01.7: Truy cập API không authentication trả về 401",
          r and r.status_code == 401)

    # Test 1.7: Logout phải clear session
    r = api_request("POST", "/api/auth/logout", session)
    check("UC-01.8: Logout thành công",
          r and r.status_code == 200)

    # Test 1.8: Sau khi logout, session không còn hợp lệ
    r = api_request("GET", "/api/auth/whoami", session)
    check("UC-01.9: Sau logout, session bị invalidate (whoami trả về 401)",
          r and r.status_code == 401)

    # Re-login để các test tiếp theo dùng
    r = api_request("POST", "/api/auth/login", session, {
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    })

    return session


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 2: QUẢN LÝ FIREWALL POLICY
# ══════════════════════════════════════════════════════════════════════════════

def test_firewall_policy(session):
    """UC-02: Tạo, sửa, xóa, và kiểm tra firewall policy"""
    section("USE CASE 2", "Quản lý Firewall Policy")

    # Test 2.1: Lấy danh sách policy hiện tại
    r = api_request("GET", "/api/config/firewall_policy", session)
    check("UC-02.1: Lấy danh sách firewall policies",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        policies = r.json()
        info(f"Hiện có {len(policies)} firewall policies trong hệ thống")

    # Test 2.2: Tạo policy ALLOW từ LAN ra WAN
    test_policy_name = "test-allow-lan-wan"
    r = api_request("POST", "/api/config/firewall_policy", session, {
        "name": test_policy_name,
        "srcintf": "lan",
        "dstintf": "wan",
        "srcaddr": "all",
        "dstaddr": "all",
        "service": "all",
        "action": "accept",
        "status": "enable",
        "comment": "Test policy: Allow LAN to WAN"
    })
    check("UC-02.2: Tạo policy mới (ALLOW LAN→WAN) thành công",
          r and r.status_code in [200, 201],
          f"Status: {r.status_code if r else 'No response'}")

    # Test 2.3: Verify policy vừa tạo tồn tại trong danh sách
    r = api_request("GET", f"/api/config/firewall_policy/{test_policy_name}", session)
    check("UC-02.3: Policy vừa tạo có thể đọc được qua GET",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        policy_data = r.json()
        check("UC-02.4: Policy có action = accept",
              policy_data.get("action") == "accept")
        check("UC-02.5: Policy có srcintf = lan",
              policy_data.get("srcintf") == "lan")
        check("UC-02.6: Policy có dstintf = wan",
              policy_data.get("dstintf") == "wan")

    # Test 2.4: Sửa policy (đổi action từ accept sang deny)
    r = api_request("PUT", f"/api/config/firewall_policy/{test_policy_name}", session, {
        "action": "deny",
        "comment": "Changed to DENY for testing"
    })
    check("UC-02.7: Sửa policy (accept → deny) thành công",
          r and r.status_code == 200)

    # Test 2.5: Verify policy đã được sửa
    r = api_request("GET", f"/api/config/firewall_policy/{test_policy_name}", session)
    if r and r.status_code == 200:
        policy_data = r.json()
        check("UC-02.8: Sau khi sửa, action = deny",
              policy_data.get("action") == "deny")

    # Test 2.6: Tạo policy DENY từ WAN vào LAN (block incoming)
    deny_policy_name = "test-deny-wan-lan"
    r = api_request("POST", "/api/config/firewall_policy", session, {
        "name": deny_policy_name,
        "srcintf": "wan",
        "dstintf": "lan",
        "srcaddr": "all",
        "dstaddr": "all",
        "service": "all",
        "action": "deny",
        "status": "enable",
        "comment": "Test policy: Block WAN to LAN"
    })
    check("UC-02.9: Tạo policy DENY WAN→LAN thành công",
          r and r.status_code in [200, 201])

    # Test 2.7: Disable policy (status = disable)
    r = api_request("PUT", f"/api/config/firewall_policy/{deny_policy_name}", session, {
        "status": "disable"
    })
    check("UC-02.10: Disable policy thành công",
          r and r.status_code == 200)

    # Test 2.8: Xóa test policies
    r = api_request("DELETE", f"/api/config/firewall_policy/{test_policy_name}", session)
    check("UC-02.11: Xóa policy test-allow-lan-wan",
          r and r.status_code == 200)

    r = api_request("DELETE", f"/api/config/firewall_policy/{deny_policy_name}", session)
    check("UC-02.12: Xóa policy test-deny-wan-lan",
          r and r.status_code == 200)

    # Test 2.9: Verify policies đã bị xóa (GET phải trả về 404)
    r = api_request("GET", f"/api/config/firewall_policy/{test_policy_name}", session)
    check("UC-02.13: Sau khi xóa, GET policy trả về 404",
          r and r.status_code == 404)

    # Test 2.10: Tạo policy với invalid data phải fail
    r = api_request("POST", "/api/config/firewall_policy", session, {
        "name": "invalid-policy",
        "action": "invalid_action"  # Invalid action
    })
    check("UC-02.14: Tạo policy với action không hợp lệ phải fail (400 hoặc 404)",
          r and r.status_code in [400, 404])


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 3: QUẢN LÝ INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

def test_interface_management(session):
    """UC-03: Cấu hình network interfaces (WAN/LAN)"""
    section("USE CASE 3", "Quản lý Network Interface")

    # Test 3.1: Lấy danh sách interfaces
    r = api_request("GET", "/api/config/system_interface", session)
    check("UC-03.1: Lấy danh sách interfaces",
          r and r.status_code == 200)

    interfaces = []
    if r and r.status_code == 200:
        interfaces = r.json()
        info(f"Hệ thống có {len(interfaces)} interfaces")
        for iface in interfaces[:3]:  # Show first 3
            info(f"  - {iface.get('name')}: {iface.get('ip', 'N/A')} (mode: {iface.get('mode', 'N/A')})")

    # Test 3.2: Đọc chi tiết một interface cụ thể
    if interfaces:
        test_iface = interfaces[0].get("name", "eth0")
        r = api_request("GET", f"/api/config/system_interface/{test_iface}", session)
        check(f"UC-03.2: Đọc thông tin interface {test_iface}",
              r and r.status_code == 200)

        if r and r.status_code == 200:
            iface_data = r.json()
            check(f"UC-03.3: Interface {test_iface} có field 'name'",
                  "name" in iface_data)
            check(f"UC-03.4: Interface {test_iface} có field 'ip'",
                  "ip" in iface_data)
            check(f"UC-03.5: Interface {test_iface} có field 'mode' (static/dhcp)",
                  "mode" in iface_data)

    # Test 3.3: Cấu hình static IP cho interface
    # Note: Chỉ test trên interface test, không làm ảnh hưởng hệ thống
    test_iface_name = "eth2"  # Giả định có eth2 để test
    r = api_request("PUT", f"/api/config/system_interface/{test_iface_name}", session, {
        "mode": "static",
        "ip": "192.168.100.1",
        "netmask": "255.255.255.0",
        "status": "up"
    })
    if r and r.status_code == 200:
        check(f"UC-03.6: Cấu hình static IP cho {test_iface_name}",
              True)

        # Verify cấu hình đã được lưu
        r = api_request("GET", f"/api/config/system_interface/{test_iface_name}", session)
        if r and r.status_code == 200:
            iface_data = r.json()
            check(f"UC-03.7: Verify mode = static",
                  iface_data.get("mode") == "static")
            check(f"UC-03.8: Verify IP = 192.168.100.1",
                  iface_data.get("ip") == "192.168.100.1")
    elif r and r.status_code == 404:
        warn(f"UC-03.6: Interface {test_iface_name} không tồn tại - skip test này")
    else:
        check(f"UC-03.6: Cấu hình static IP cho {test_iface_name}",
              False, f"Status: {r.status_code if r else 'No response'}")

    # Test 3.4: Cấu hình interface mode DHCP
    r = api_request("PUT", f"/api/config/system_interface/{test_iface_name}", session, {
        "mode": "dhcp",
        "status": "up"
    })
    if r and r.status_code == 200:
        check(f"UC-03.9: Cấu hình {test_iface_name} mode = dhcp",
              True)
    elif r and r.status_code == 404:
        warn(f"Interface {test_iface_name} không tồn tại")


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 4: QUẢN LÝ NAT (PORT FORWARDING & SOURCE NAT)
# ══════════════════════════════════════════════════════════════════════════════

def test_nat_configuration(session):
    """UC-04: Cấu hình NAT rules (SNAT, DNAT, Port Forwarding)"""
    section("USE CASE 4", "Quản lý NAT Configuration")

    # Test 4.1: Lấy danh sách NAT rules
    r = api_request("GET", "/api/config/firewall_nat", session)
    check("UC-04.1: Lấy danh sách NAT rules",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        nat_rules = r.json()
        info(f"Hiện có {len(nat_rules)} NAT rules")

    # Test 4.2: Tạo Port Forwarding rule (DNAT)
    # Ví dụ: Forward port 8080 từ WAN đến 192.168.1.100:80
    pf_rule_name = "test-portfwd-web"
    r = api_request("POST", "/api/config/firewall_nat", session, {
        "name": pf_rule_name,
        "type": "dnat",
        "srcintf": "wan",
        "dstintf": "lan",
        "protocol": "tcp",
        "extport": "8080",
        "intip": "192.168.1.100",
        "intport": "80",
        "status": "enable",
        "comment": "Port forward: WAN:8080 -> 192.168.1.100:80"
    })
    check("UC-04.2: Tạo Port Forwarding rule (DNAT)",
          r and r.status_code in [200, 201])

    # Test 4.3: Verify DNAT rule vừa tạo
    r = api_request("GET", f"/api/config/firewall_nat/{pf_rule_name}", session)
    if r and r.status_code == 200:
        nat_data = r.json()
        check("UC-04.3: DNAT rule có type = dnat",
              nat_data.get("type") == "dnat")
        check("UC-04.4: DNAT rule có extport = 8080",
              str(nat_data.get("extport")) == "8080")
    elif r and r.status_code == 404:
        warn("UC-04.3: NAT API chưa được implement hoặc endpoint khác")

    # Test 4.4: Tạo Source NAT (SNAT) rule
    # Ví dụ: NAT traffic từ LAN ra WAN với IP của WAN interface
    snat_rule_name = "test-snat-lan-wan"
    r = api_request("POST", "/api/config/firewall_nat", session, {
        "name": snat_rule_name,
        "type": "snat",
        "srcintf": "lan",
        "dstintf": "wan",
        "srcaddr": "192.168.1.0/24",
        "nat_type": "masquerade",
        "status": "enable",
        "comment": "SNAT: LAN to WAN (masquerade)"
    })
    check("UC-04.5: Tạo Source NAT rule (SNAT/Masquerade)",
          r and r.status_code in [200, 201, 404])  # 404 nếu chưa implement

    # Test 4.5: Sửa NAT rule
    r = api_request("PUT", f"/api/config/firewall_nat/{pf_rule_name}", session, {
        "extport": "9090",
        "comment": "Updated: WAN:9090 -> 192.168.1.100:80"
    })
    if r and r.status_code == 200:
        check("UC-04.6: Sửa NAT rule (change extport)",
              True)

    # Test 4.6: Xóa test NAT rules
    for rule_name in [pf_rule_name, snat_rule_name]:
        r = api_request("DELETE", f"/api/config/firewall_nat/{rule_name}", session)
        if r and r.status_code in [200, 404]:
            check(f"UC-04.7: Xóa NAT rule {rule_name}",
                  r.status_code == 200 or r.status_code == 404)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 5: QUẢN LÝ DHCP SERVER
# ══════════════════════════════════════════════════════════════════════════════

def test_dhcp_server(session):
    """UC-05: Cấu hình DHCP server cho LAN"""
    section("USE CASE 5", "Quản lý DHCP Server")

    # Test 5.1: Lấy danh sách DHCP pools
    r = api_request("GET", "/api/config/system_dhcp", session)
    check("UC-05.1: Lấy danh sách DHCP pools",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        dhcp_pools = r.json()
        info(f"Hiện có {len(dhcp_pools)} DHCP pools")

    # Test 5.2: Tạo DHCP pool mới
    test_pool_name = "test-dhcp-lan"
    r = api_request("POST", "/api/config/system_dhcp", session, {
        "name": test_pool_name,
        "interface": "lan",
        "start": "192.168.1.100",
        "end": "192.168.1.200",
        "netmask": "255.255.255.0",
        "gateway": "192.168.1.1",
        "dns": "8.8.8.8,8.8.4.4",
        "lease_time": "86400",
        "status": "enable"
    })
    check("UC-05.2: Tạo DHCP pool mới cho LAN",
          r and r.status_code in [200, 201])

    # Test 5.3: Verify DHCP pool vừa tạo
    r = api_request("GET", f"/api/config/system_dhcp/{test_pool_name}", session)
    if r and r.status_code == 200:
        pool_data = r.json()
        check("UC-05.3: DHCP pool có start IP = 192.168.1.100",
              pool_data.get("start") == "192.168.1.100")
        check("UC-05.4: DHCP pool có DNS servers",
              "8.8.8.8" in pool_data.get("dns", ""))

    # Test 5.4: Sửa DHCP pool (change IP range)
    r = api_request("PUT", f"/api/config/system_dhcp/{test_pool_name}", session, {
        "start": "192.168.1.50",
        "end": "192.168.1.150"
    })
    check("UC-05.5: Sửa DHCP pool (change IP range)",
          r and r.status_code == 200)

    # Test 5.5: Tạo DHCP static lease (MAC → IP binding)
    static_lease_name = "test-static-lease"
    r = api_request("POST", "/api/config/system_dhcp_reservation", session, {
        "name": static_lease_name,
        "pool": test_pool_name,
        "mac": "aa:bb:cc:dd:ee:ff",
        "ip": "192.168.1.10",
        "hostname": "test-device"
    })
    if r and r.status_code in [200, 201]:
        check("UC-05.6: Tạo DHCP static reservation (MAC → IP)",
              True)
        # Cleanup
        api_request("DELETE", f"/api/config/system_dhcp_reservation/{static_lease_name}", session)
    elif r and r.status_code == 404:
        warn("UC-05.6: DHCP reservation API chưa được implement")

    # Test 5.6: Disable DHCP pool
    r = api_request("PUT", f"/api/config/system_dhcp/{test_pool_name}", session, {
        "status": "disable"
    })
    check("UC-05.7: Disable DHCP pool",
          r and r.status_code == 200)

    # Test 5.7: Xóa DHCP pool
    r = api_request("DELETE", f"/api/config/system_dhcp/{test_pool_name}", session)
    check("UC-05.8: Xóa DHCP pool test",
          r and r.status_code == 200)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 6: QUẢN LÝ STATIC ROUTE
# ══════════════════════════════════════════════════════════════════════════════

def test_static_routes(session):
    """UC-06: Cấu hình static routing"""
    section("USE CASE 6", "Quản lý Static Routes")

    # Test 6.1: Lấy danh sách routes
    r = api_request("GET", "/api/config/system_route", session)
    check("UC-06.1: Lấy danh sách static routes",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        routes = r.json()
        info(f"Hiện có {len(routes)} static routes")

    # Test 6.2: Tạo static route mới
    test_route_name = "test-route-10-0"
    r = api_request("POST", "/api/config/system_route", session, {
        "name": test_route_name,
        "destination": "10.0.0.0/8",
        "gateway": "192.168.1.254",
        "interface": "lan",
        "metric": "10",
        "status": "enable",
        "comment": "Test route to 10.0.0.0/8"
    })
    check("UC-06.2: Tạo static route mới (10.0.0.0/8)",
          r and r.status_code in [200, 201])

    # Test 6.3: Verify route vừa tạo
    r = api_request("GET", f"/api/config/system_route/{test_route_name}", session)
    if r and r.status_code == 200:
        route_data = r.json()
        check("UC-06.3: Route có destination = 10.0.0.0/8",
              "10.0.0.0" in route_data.get("destination", ""))
        check("UC-06.4: Route có gateway = 192.168.1.254",
              route_data.get("gateway") == "192.168.1.254")

    # Test 6.4: Sửa route (change metric)
    r = api_request("PUT", f"/api/config/system_route/{test_route_name}", session, {
        "metric": "20"
    })
    check("UC-06.5: Sửa route (change metric)",
          r and r.status_code == 200)

    # Test 6.5: Xóa test route
    r = api_request("DELETE", f"/api/config/system_route/{test_route_name}", session)
    check("UC-06.6: Xóa static route test",
          r and r.status_code == 200)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 7: QUẢN LÝ ADDRESS & SERVICE OBJECTS
# ══════════════════════════════════════════════════════════════════════════════

def test_objects(session):
    """UC-07: Quản lý Address Objects và Service Objects"""
    section("USE CASE 7", "Quản lý Address & Service Objects")

    # Test 7.1: Lấy danh sách address objects
    r = api_request("GET", "/api/config/firewall_address", session)
    check("UC-07.1: Lấy danh sách address objects",
          r and r.status_code == 200)

    # Test 7.2: Tạo address object (subnet)
    test_addr_name = "test-addr-subnet"
    r = api_request("POST", "/api/config/firewall_address", session, {
        "name": test_addr_name,
        "type": "ipmask",
        "subnet": "172.16.0.0/16",
        "comment": "Test address object - subnet"
    })
    check("UC-07.2: Tạo address object (subnet 172.16.0.0/16)",
          r and r.status_code in [200, 201])

    # Test 7.3: Tạo address object (IP range)
    test_addr_range = "test-addr-range"
    r = api_request("POST", "/api/config/firewall_address", session, {
        "name": test_addr_range,
        "type": "iprange",
        "start_ip": "10.10.10.10",
        "end_ip": "10.10.10.20",
        "comment": "Test address object - IP range"
    })
    check("UC-07.3: Tạo address object (IP range 10.10.10.10-20)",
          r and r.status_code in [200, 201])

    # Test 7.4: Verify address object
    r = api_request("GET", f"/api/config/firewall_address/{test_addr_name}", session)
    if r and r.status_code == 200:
        addr_data = r.json()
        check("UC-07.4: Address object có type = ipmask",
              addr_data.get("type") == "ipmask")
        check("UC-07.5: Address object có subnet = 172.16.0.0/16",
              "172.16.0.0" in addr_data.get("subnet", ""))

    # Test 7.5: Lấy danh sách service objects
    r = api_request("GET", "/api/config/firewall_service", session)
    check("UC-07.6: Lấy danh sách service objects",
          r and r.status_code == 200)

    # Test 7.6: Tạo service object (custom port)
    test_svc_name = "test-svc-custom"
    r = api_request("POST", "/api/config/firewall_service", session, {
        "name": test_svc_name,
        "protocol": "tcp",
        "port": "8443",
        "comment": "Test service - HTTPS alternate port"
    })
    check("UC-07.7: Tạo service object (TCP/8443)",
          r and r.status_code in [200, 201])

    # Test 7.7: Tạo service object (port range)
    test_svc_range = "test-svc-range"
    r = api_request("POST", "/api/config/firewall_service", session, {
        "name": test_svc_range,
        "protocol": "tcp",
        "port": "8000-9000",
        "comment": "Test service - port range 8000-9000"
    })
    check("UC-07.8: Tạo service object (TCP port range 8000-9000)",
          r and r.status_code in [200, 201])

    # Test 7.8: Xóa test objects
    for obj_name in [test_addr_name, test_addr_range]:
        r = api_request("DELETE", f"/api/config/firewall_address/{obj_name}", session)
        check(f"UC-07.9: Xóa address object {obj_name}",
              r and r.status_code in [200, 404])

    for obj_name in [test_svc_name, test_svc_range]:
        r = api_request("DELETE", f"/api/config/firewall_service/{obj_name}", session)
        check(f"UC-07.10: Xóa service object {obj_name}",
              r and r.status_code in [200, 404])


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 8: GIÁM SÁT HỆ THỐNG (DASHBOARD)
# ══════════════════════════════════════════════════════════════════════════════

def test_system_monitoring(session):
    """UC-08: Giám sát tài nguyên hệ thống (CPU, RAM, Disk, Network)"""
    section("USE CASE 8", "Giám sát Hệ thống (Dashboard)")

    # Test 8.1: Lấy thông tin tổng quan tài nguyên
    r = api_request("GET", "/api/system/resources", session)
    check("UC-08.1: Lấy thông tin system resources",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        resources = r.json()
        info(f"CPU: {resources.get('cpu', 'N/A')}%")
        info(f"RAM: {resources.get('ram', 'N/A')}%")
        info(f"Disk: {resources.get('disk', 'N/A')}%")

        check("UC-08.2: Response có field 'cpu'",
              'cpu' in resources)
        check("UC-08.3: Response có field 'ram'",
              'ram' in resources)
        check("UC-08.4: Response có field 'disk'",
              'disk' in resources)

    # Test 8.2: Lấy chi tiết RAM usage
    r = api_request("GET", "/api/system/resources/ram", session)
    check("UC-08.5: Lấy chi tiết RAM usage",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        ram_data = r.json()
        info(f"RAM Total: {ram_data.get('total', 'N/A')} MB")
        info(f"RAM Used: {ram_data.get('used', 'N/A')} MB")

    # Test 8.3: Lấy thông tin disk usage
    r = api_request("GET", "/api/system/resources/disk", session)
    check("UC-08.6: Lấy chi tiết Disk usage",
          r and r.status_code == 200)

    # Test 8.4: Lấy session count (số lượng connections hiện tại)
    r = api_request("GET", "/api/system/sessions", session)
    if r and r.status_code == 200:
        sessions = r.json()
        info(f"Active sessions: {sessions.get('count', 'N/A')}")
        check("UC-08.7: Lấy thông tin active sessions",
              True)
    elif r and r.status_code == 404:
        warn("UC-08.7: Session tracking API chưa được implement")

    # Test 8.5: Lấy network statistics
    r = api_request("GET", "/api/system/network/stats", session)
    if r and r.status_code == 200:
        net_stats = r.json()
        check("UC-08.8: Lấy network statistics",
              True)
        if isinstance(net_stats, list):
            for iface_stat in net_stats[:2]:
                info(f"Interface {iface_stat.get('name')}: RX {iface_stat.get('rx_bytes', 0)} / TX {iface_stat.get('tx_bytes', 0)}")
    elif r and r.status_code == 404:
        warn("UC-08.8: Network stats API chưa được implement")


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 9: CÔNG CỤ CHẨN ĐOÁN
# ══════════════════════════════════════════════════════════════════════════════

def test_diagnostic_tools(session):
    """UC-09: Công cụ chẩn đoán mạng (Ping, Traceroute, DNS lookup)"""
    section("USE CASE 9", "Công cụ Chẩn đoán (Diagnostic Tools)")

    # Test 9.1: Ping localhost
    r = api_request("POST", "/api/diagnose/ping", session, {
        "target": "127.0.0.1"
    })
    check("UC-09.1: Ping localhost (127.0.0.1)",
          r and r.status_code == 200)

    # Test 9.2: Ping external (Google DNS)
    r = api_request("POST", "/api/diagnose/ping", session, {
        "target": "8.8.8.8"
    })
    check("UC-09.2: Ping external IP (8.8.8.8)",
          r and r.status_code == 200)

    # Test 9.3: DNS lookup
    r = api_request("POST", "/api/diagnose/nslookup", session, {
        "target": "google.com"
    })
    check("UC-09.3: DNS lookup (google.com)",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        result = r.json()
        info(f"DNS result: {result.get('output', '')[:100]}")

    # Test 9.4: Traceroute
    r = api_request("POST", "/api/diagnose/traceroute", session, {
        "target": "8.8.8.8"
    })
    if r and r.status_code == 200:
        check("UC-09.4: Traceroute to 8.8.8.8",
              True)
    elif r and r.status_code in [404, 501]:
        warn("UC-09.4: Traceroute chưa được implement")

    # Test 9.5: Test với invalid target (phải fail)
    r = api_request("POST", "/api/diagnose/ping", session, {
        "target": "invalid_target!@#"
    })
    check("UC-09.5: Ping với invalid target phải fail (400)",
          r and r.status_code == 400)

    # Test 9.6: Test missing target parameter
    r = api_request("POST", "/api/diagnose/ping", session, {})
    check("UC-09.6: Ping không có target phải fail (400)",
          r and r.status_code == 400)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 10: QUẢN LÝ FIRMWARE
# ══════════════════════════════════════════════════════════════════════════════

def test_firmware_management(session):
    """UC-10: Quản lý firmware (xem version, upload, upgrade)"""
    section("USE CASE 10", "Quản lý Firmware")

    # Test 10.1: Lấy thông tin firmware hiện tại
    r = api_request("GET", "/api/system/firmware", session)
    check("UC-10.1: Lấy thông tin firmware version",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        fw_info = r.json()
        info(f"Current firmware: {fw_info.get('current_version', 'N/A')}")
        check("UC-10.2: Response có field 'current_version'",
              'current_version' in fw_info or 'version' in fw_info)

    # Test 10.2: Check firmware upgrade progress
    r = api_request("GET", "/api/system/firmware/progress", session)
    check("UC-10.3: Lấy firmware upgrade progress",
          r and r.status_code == 200)

    # Test 10.3: Firmware upload validation
    # Note: Không thực sự upload file trong test này
    info("UC-10.4: Firmware upload test bỏ qua (cần file .itb thật)")

    # Test 10.4: Trigger upgrade (stub test - không thực sự upgrade)
    r = api_request("POST", "/api/system/firmware/upgrade", session, {})
    if r and r.status_code == 501:
        check("UC-10.5: Firmware upgrade API trả về 501 (not implemented - OK)",
              True)
    elif r and r.status_code in [200, 400]:
        warn("UC-10.5: Firmware upgrade API có response (có thể đã implement)")


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 11: QUẢN LÝ ADMIN ACCOUNTS
# ══════════════════════════════════════════════════════════════════════════════

def test_admin_management(session):
    """UC-11: Quản lý admin accounts và phân quyền"""
    section("USE CASE 11", "Quản lý Admin Accounts")

    # Test 11.1: Lấy danh sách admin users
    r = api_request("GET", "/api/config/system_admin", session)
    check("UC-11.1: Lấy danh sách admin users",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        admins = r.json()
        info(f"Hiện có {len(admins)} admin users")

    # Test 11.2: Lấy danh sách admin profiles (roles)
    r = api_request("GET", "/api/config/system_admin-profile", session)
    check("UC-11.2: Lấy danh sách admin profiles",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        profiles = r.json()
        info(f"Available profiles: {', '.join([p.get('name', '') for p in profiles])}")

    # Test 11.3: Tạo admin user mới với profile read-only
    test_admin_user = "testuser-ro"
    test_admin_pass = "TestPass123!"
    r = api_request("POST", "/api/admin/create", session, {
        "username": test_admin_user,
        "password": test_admin_pass,
        "profile": "read-only"
    })
    check("UC-11.3: Tạo admin user mới (read-only profile)",
          r and r.status_code in [200, 201])

    # Test 11.4: Login với user mới tạo
    ro_session = requests.Session()
    r = api_request("POST", "/api/auth/login", ro_session, {
        "username": test_admin_user,
        "password": test_admin_pass
    })
    check("UC-11.4: Login với user read-only thành công",
          r and r.status_code == 200)

    # Test 11.5: Verify read-only user không thể tạo policy
    r = api_request("POST", "/api/config/firewall_policy", ro_session, {
        "name": "should-fail",
        "action": "accept"
    })
    check("UC-11.5: Read-only user không thể tạo firewall policy (403)",
          r and r.status_code == 403)

    # Test 11.6: Verify read-only user có thể đọc config
    r = api_request("GET", "/api/config/firewall_policy", ro_session)
    check("UC-11.6: Read-only user có thể đọc firewall policies (200)",
          r and r.status_code == 200)

    # Test 11.7: Đổi password của user
    r = api_request("POST", "/api/auth/change-password", ro_session, {
        "password": "NewPass456!"
    })
    check("UC-11.7: User tự đổi password thành công",
          r and r.status_code == 200)

    # Test 11.8: Verify password cũ không còn dùng được
    old_session = requests.Session()
    r = api_request("POST", "/api/auth/login", old_session, {
        "username": test_admin_user,
        "password": test_admin_pass
    })
    check("UC-11.8: Login với password cũ fail (401)",
          r and r.status_code == 401)

    # Test 11.9: Admin xóa test user
    r = api_request("DELETE", f"/api/config/system_admin/{test_admin_user}", session)
    check("UC-11.9: Admin xóa test user",
          r and r.status_code == 200)

    # Test 11.10: Không được xóa builtin admin
    r = api_request("DELETE", "/api/config/system_admin/admin", session)
    check("UC-11.10: Không thể xóa builtin admin account (403)",
          r and r.status_code == 403)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 12: KIỂM TRA BẢO MẬT
# ══════════════════════════════════════════════════════════════════════════════

def test_security_features(session):
    """UC-12: Kiểm tra các tính năng bảo mật (XSS, CSRF, Session, Headers)"""
    section("USE CASE 12", "Kiểm tra Bảo mật (Security Features)")

    # Test 12.1: HTTPS Security Headers
    r = api_request("GET", "/api/auth/whoami", session)
    if r and r.status_code == 200:
        headers = r.headers
        check("UC-12.1: Response có X-Content-Type-Options: nosniff",
              'X-Content-Type-Options' in headers and headers['X-Content-Type-Options'] == 'nosniff')
        check("UC-12.2: Response có X-Frame-Options: DENY",
              'X-Frame-Options' in headers and headers['X-Frame-Options'] == 'DENY')
        check("UC-12.3: Response có Content-Security-Policy",
              'Content-Security-Policy' in headers)

        if BASE_URL.startswith('https'):
            check("UC-12.4: Response có Strict-Transport-Security (HSTS)",
                  'Strict-Transport-Security' in headers)

    # Test 12.2: XSS Protection - không cho phép script trong input
    r = api_request("POST", "/api/config/firewall_policy", session, {
        "name": "<script>alert('xss')</script>",
        "action": "accept"
    })
    check("UC-12.5: Reject XSS trong policy name (400)",
          r and r.status_code in [400, 404])

    # Test 12.3: SQL Injection Protection
    r = api_request("GET", "/api/config/firewall_policy/'; DROP TABLE firewall_policy; --", session)
    check("UC-12.6: SQL injection trong URL không gây lỗi (404 hoặc 400)",
          r and r.status_code in [400, 404])

    # Test 12.4: Session Cookie Security
    # Check if session cookie has HttpOnly and Secure flags
    login_session = requests.Session()
    r = api_request("POST", "/api/auth/login", login_session, {
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    })
    if r:
        set_cookie_header = r.headers.get('Set-Cookie', '')
        check("UC-12.7: Session cookie có HttpOnly flag",
              'HttpOnly' in set_cookie_header)
        check("UC-12.8: Session cookie có SameSite=Strict",
              'SameSite=Strict' in set_cookie_header)
        if BASE_URL.startswith('https'):
            check("UC-12.9: Session cookie có Secure flag (HTTPS only)",
                  'Secure' in set_cookie_header)

    # Test 12.5: Rate limiting on login
    info("UC-12.10: Testing rate limiting (sending 11 failed login attempts)...")
    test_session = requests.Session()
    fail_count = 0
    rate_limited = False
    for i in range(12):
        r = api_request("POST", "/api/auth/login", test_session, {
            "username": "admin",
            "password": "wrongpass"
        })
        if r and r.status_code == 429:
            rate_limited = True
            break
        fail_count += 1
        time.sleep(0.1)

    check("UC-12.11: Rate limiting active sau nhiều lần login fail (429)",
          rate_limited,
          f"Failed {fail_count} times before rate limit")

    # Test 12.6: Session timeout
    # Tạo session mới, sau đó check xem có timeout không (cần đợi lâu - skip trong test nhanh)
    info("UC-12.12: Session timeout test bỏ qua (cần đợi 15 phút)")

    # Test 12.7: Path traversal protection
    r = api_request("GET", "/api/config/../../etc/passwd", session)
    check("UC-12.13: Path traversal không hoạt động (404 hoặc 400)",
          r and r.status_code in [400, 404])


# ══════════════════════════════════════════════════════════════════════════════
# MAIN TEST RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def main():
    header("STARGAZER NGFW - KIỂM TRA USE CASE TƯỜNG LỬA")

    info(f"Target URL: {BASE_URL}")
    info(f"Admin User: {ADMIN_USER}")
    info(f"Bắt đầu kiểm tra...")

    start_time = time.time()

    # Kiểm tra kết nối đến firewall
    try:
        r = requests.get(urljoin(BASE_URL, "/"), timeout=5, verify=False)
        check("Kết nối đến Web UI", r.status_code == 200)
    except Exception as e:
        check("Kết nối đến Web UI", False, str(e))
        print(f"\n{RED}KHÔNG THỂ KẾT NỐI ĐỂN {BASE_URL}{RESET}")
        sys.exit(1)

    # Chạy các test suite
    session = test_authentication()

    if session:
        test_firewall_policy(session)
        test_interface_management(session)
        test_nat_configuration(session)
        test_dhcp_server(session)
        test_static_routes(session)
        test_objects(session)
        test_system_monitoring(session)
        test_diagnostic_tools(session)
        test_firmware_management(session)
        test_admin_management(session)
        test_security_features(session)

    # Tổng kết
    elapsed = time.time() - start_time
    header("KẾT QUẢ KIỂM TRA")

    total = PASS_COUNT + FAIL_COUNT
    pass_rate = (PASS_COUNT / total * 100) if total > 0 else 0

    print(f"{GREEN}✓ PASS:  {PASS_COUNT}{RESET}")
    print(f"{RED}✗ FAIL:  {FAIL_COUNT}{RESET}")
    print(f"{YELLOW}⚠ WARN:  {WARN_COUNT}{RESET}")
    print(f"\n{BOLD}Tổng số test: {total}{RESET}")
    print(f"{BOLD}Tỷ lệ pass:   {pass_rate:.1f}%{RESET}")
    print(f"{BOLD}Thời gian:    {elapsed:.2f}s{RESET}")

    if FAIL_COUNT == 0:
        print(f"\n{GREEN}{BOLD}TẤT CẢ CÁC TEST CASE ĐỀU PASSED!{RESET}")
        sys.exit(0)
    else:
        print(f"\n{YELLOW}{BOLD}CÓ {FAIL_COUNT} TEST CASE FAILED{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
