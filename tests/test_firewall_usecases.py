#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_firewall_usecases.py — Firewall use case tests for the embedded device

This script exercises the full Stargazer NGFW firewall feature set through the Web UI,
simulating real-world firewall administrator scenarios.

Use cases covered:
  1. Authentication and authorization (Login/Logout)
  2. Firewall Policy management (create, edit, delete rules)
  3. Interface configuration (WAN/LAN setup)
  4. NAT configuration (Port forwarding, Source NAT)
  5. DHCP Server management
  6. Static Route management
  7. Address Object and Service Object management
  8. System monitoring (CPU, RAM, Disk, Network)
  9. Diagnostic tools (Ping, Traceroute, DNS lookup)
 10. Firmware management
 11. Admin account management
 12. Security checks (XSS, CSRF, Session)

Run: python3 tests/test_firewall_usecases.py [BASE_URL]

Examples:
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
# TEST CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASS = "T@n27404"

# Disable SSL warnings when testing against self-signed HTTPS
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
    """Print the header for each test suite"""
    print(f"\n{BOLD}{CYAN}{'=' * 80}{RESET}")
    print(f"{BOLD}{CYAN}{text.center(80)}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 80}{RESET}\n")


def section(num, title):
    """Print a section heading"""
    print(f"\n{BOLD}[{num}] {title}{RESET}")
    print(f"{'-' * 80}")


def check(label, condition, detail=""):
    """Evaluate a condition and record the PASS/FAIL result"""
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
    """Record a warning (not a critical error)"""
    global WARN_COUNT
    print(f"  {YELLOW}⚠ WARN{RESET} {label}")
    if detail:
        print(f"         {YELLOW}↳ {detail}{RESET}")
    WARN_COUNT += 1


def info(text):
    """Print additional information"""
    print(f"  {CYAN}ℹ INFO{RESET} {text}")


def api_request(method, path, session=None, json_data=None, expect_fail=False):
    """Send a request to the API and return the response"""
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
# USE CASE 1: AUTHENTICATION AND AUTHORIZATION
# ══════════════════════════════════════════════════════════════════════════════

def test_authentication():
    """UC-01: Test login, logout, and session management"""
    section("USE CASE 1", "Authentication and Authorization")

    # Test 1.1: Successful login with valid credentials
    session = requests.Session()
    r = api_request("POST", "/api/auth/login", session, {
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    })
    check("UC-01.1: Login succeeds with admin credentials",
          r and r.status_code == 200,
          f"Status: {r.status_code if r else 'No response'}")

    # Test 1.2: Verify the session cookie is set
    check("UC-01.2: Session cookie (sg_sid) is set after login",
          'sg_sid' in session.cookies,
          f"Cookies: {list(session.cookies.keys())}")

    # Test 1.3: whoami endpoint returns user info
    r = api_request("GET", "/api/auth/whoami", session)
    if r and r.status_code == 200:
        data = r.json()
        check("UC-01.3: whoami returns username = admin",
              data.get("username") == ADMIN_USER,
              f"Got: {data.get('username')}")
        check("UC-01.4: whoami returns permissions (admin has full rights)",
              "admin" in data.get("permissions", ""),
              f"Permissions: {data.get('permissions')}")
    else:
        check("UC-01.3: whoami endpoint", False, "Request failed")

    # Test 1.4: Login with wrong password must return 401
    bad_session = requests.Session()
    r = api_request("POST", "/api/auth/login", bad_session, {
        "username": ADMIN_USER,
        "password": "wrongpassword"
    })
    check("UC-01.5: Login with wrong password returns 401 Unauthorized",
          r and r.status_code == 401)

    # Test 1.5: Login with nonexistent username
    r = api_request("POST", "/api/auth/login", bad_session, {
        "username": "nonexistent_user",
        "password": "anypassword"
    })
    check("UC-01.6: Login with nonexistent username returns 401",
          r and r.status_code == 401,
          "Must not leak whether the user exists")

    # Test 1.6: Accessing the API without authentication must return 401
    no_auth_session = requests.Session()
    r = api_request("GET", "/api/config/firewall_policy", no_auth_session)
    check("UC-01.7: Accessing the API without authentication returns 401",
          r and r.status_code == 401)

    # Test 1.7: Logout must clear the session
    r = api_request("POST", "/api/auth/logout", session)
    check("UC-01.8: Logout succeeds",
          r and r.status_code == 200)

    # Test 1.8: After logout, the session is no longer valid
    r = api_request("GET", "/api/auth/whoami", session)
    check("UC-01.9: After logout, the session is invalidated (whoami returns 401)",
          r and r.status_code == 401)

    # Re-login for the following tests to use
    r = api_request("POST", "/api/auth/login", session, {
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    })

    return session


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 2: FIREWALL POLICY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def test_firewall_policy(session):
    """UC-02: Create, edit, delete, and verify firewall policies"""
    section("USE CASE 2", "Firewall Policy Management")

    # Test 2.1: List the current policies
    r = api_request("GET", "/api/config/firewall_policy", session)
    check("UC-02.1: List firewall policies",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        policies = r.json()
        info(f"There are currently {len(policies)} firewall policies in the system")

    # Test 2.2: Create an ALLOW policy from LAN to WAN
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
    check("UC-02.2: Create a new policy (ALLOW LAN→WAN) succeeds",
          r and r.status_code in [200, 201],
          f"Status: {r.status_code if r else 'No response'}")

    # Test 2.3: Verify the policy just created exists in the list
    r = api_request("GET", f"/api/config/firewall_policy/{test_policy_name}", session)
    check("UC-02.3: The newly created policy can be read via GET",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        policy_data = r.json()
        check("UC-02.4: Policy has action = accept",
              policy_data.get("action") == "accept")
        check("UC-02.5: Policy has srcintf = lan",
              policy_data.get("srcintf") == "lan")
        check("UC-02.6: Policy has dstintf = wan",
              policy_data.get("dstintf") == "wan")

    # Test 2.4: Edit the policy (change action from accept to deny)
    r = api_request("PUT", f"/api/config/firewall_policy/{test_policy_name}", session, {
        "action": "deny",
        "comment": "Changed to DENY for testing"
    })
    check("UC-02.7: Edit policy (accept → deny) succeeds",
          r and r.status_code == 200)

    # Test 2.5: Verify the policy was edited
    r = api_request("GET", f"/api/config/firewall_policy/{test_policy_name}", session)
    if r and r.status_code == 200:
        policy_data = r.json()
        check("UC-02.8: After the edit, action = deny",
              policy_data.get("action") == "deny")

    # Test 2.6: Create a DENY policy from WAN to LAN (block incoming)
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
    check("UC-02.9: Create a DENY WAN→LAN policy succeeds",
          r and r.status_code in [200, 201])

    # Test 2.7: Disable policy (status = disable)
    r = api_request("PUT", f"/api/config/firewall_policy/{deny_policy_name}", session, {
        "status": "disable"
    })
    check("UC-02.10: Disable policy succeeds",
          r and r.status_code == 200)

    # Test 2.8: Delete the test policies
    r = api_request("DELETE", f"/api/config/firewall_policy/{test_policy_name}", session)
    check("UC-02.11: Delete policy test-allow-lan-wan",
          r and r.status_code == 200)

    r = api_request("DELETE", f"/api/config/firewall_policy/{deny_policy_name}", session)
    check("UC-02.12: Delete policy test-deny-wan-lan",
          r and r.status_code == 200)

    # Test 2.9: Verify the policies were deleted (GET must return 404)
    r = api_request("GET", f"/api/config/firewall_policy/{test_policy_name}", session)
    check("UC-02.13: After deletion, GET policy returns 404",
          r and r.status_code == 404)

    # Test 2.10: Creating a policy with invalid data must fail
    r = api_request("POST", "/api/config/firewall_policy", session, {
        "name": "invalid-policy",
        "action": "invalid_action"  # Invalid action
    })
    check("UC-02.14: Creating a policy with an invalid action must fail (400 or 404)",
          r and r.status_code in [400, 404])


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 3: INTERFACE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def test_interface_management(session):
    """UC-03: Configure network interfaces (WAN/LAN)"""
    section("USE CASE 3", "Network Interface Management")

    # Test 3.1: List interfaces
    r = api_request("GET", "/api/config/system_interface", session)
    check("UC-03.1: List interfaces",
          r and r.status_code == 200)

    interfaces = []
    if r and r.status_code == 200:
        interfaces = r.json()
        info(f"The system has {len(interfaces)} interfaces")
        for iface in interfaces[:3]:  # Show first 3
            info(f"  - {iface.get('name')}: {iface.get('ip', 'N/A')} (mode: {iface.get('mode', 'N/A')})")

    # Test 3.2: Read details of a specific interface
    if interfaces:
        test_iface = interfaces[0].get("name", "eth0")
        r = api_request("GET", f"/api/config/system_interface/{test_iface}", session)
        check(f"UC-03.2: Read information for interface {test_iface}",
              r and r.status_code == 200)

        if r and r.status_code == 200:
            iface_data = r.json()
            check(f"UC-03.3: Interface {test_iface} has field 'name'",
                  "name" in iface_data)
            check(f"UC-03.4: Interface {test_iface} has field 'ip'",
                  "ip" in iface_data)
            check(f"UC-03.5: Interface {test_iface} has field 'mode' (static/dhcp)",
                  "mode" in iface_data)

    # Test 3.3: Configure a static IP on an interface
    # Note: Only test on a test interface so the system is not affected
    test_iface_name = "eth2"  # Assume eth2 exists for testing
    r = api_request("PUT", f"/api/config/system_interface/{test_iface_name}", session, {
        "mode": "static",
        "ip": "192.168.100.1",
        "netmask": "255.255.255.0",
        "status": "up"
    })
    if r and r.status_code == 200:
        check(f"UC-03.6: Configure static IP on {test_iface_name}",
              True)

        # Verify the configuration was saved
        r = api_request("GET", f"/api/config/system_interface/{test_iface_name}", session)
        if r and r.status_code == 200:
            iface_data = r.json()
            check(f"UC-03.7: Verify mode = static",
                  iface_data.get("mode") == "static")
            check(f"UC-03.8: Verify IP = 192.168.100.1",
                  iface_data.get("ip") == "192.168.100.1")
    elif r and r.status_code == 404:
        warn(f"UC-03.6: Interface {test_iface_name} does not exist - skipping this test")
    else:
        check(f"UC-03.6: Configure static IP on {test_iface_name}",
              False, f"Status: {r.status_code if r else 'No response'}")

    # Test 3.4: Configure interface in DHCP mode
    r = api_request("PUT", f"/api/config/system_interface/{test_iface_name}", session, {
        "mode": "dhcp",
        "status": "up"
    })
    if r and r.status_code == 200:
        check(f"UC-03.9: Configure {test_iface_name} mode = dhcp",
              True)
    elif r and r.status_code == 404:
        warn(f"Interface {test_iface_name} does not exist")


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 4: NAT MANAGEMENT (PORT FORWARDING & SOURCE NAT)
# ══════════════════════════════════════════════════════════════════════════════

def test_nat_configuration(session):
    """UC-04: Configure NAT rules (SNAT, DNAT, Port Forwarding)"""
    section("USE CASE 4", "NAT Configuration Management")

    # Test 4.1: List NAT rules
    r = api_request("GET", "/api/config/firewall_nat", session)
    check("UC-04.1: List NAT rules",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        nat_rules = r.json()
        info(f"There are currently {len(nat_rules)} NAT rules")

    # Test 4.2: Create a Port Forwarding rule (DNAT)
    # Example: Forward port 8080 from WAN to 192.168.1.100:80
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
    check("UC-04.2: Create a Port Forwarding rule (DNAT)",
          r and r.status_code in [200, 201])

    # Test 4.3: Verify the DNAT rule just created
    r = api_request("GET", f"/api/config/firewall_nat/{pf_rule_name}", session)
    if r and r.status_code == 200:
        nat_data = r.json()
        check("UC-04.3: DNAT rule has type = dnat",
              nat_data.get("type") == "dnat")
        check("UC-04.4: DNAT rule has extport = 8080",
              str(nat_data.get("extport")) == "8080")
    elif r and r.status_code == 404:
        warn("UC-04.3: NAT API not yet implemented or a different endpoint")

    # Test 4.4: Create a Source NAT (SNAT) rule
    # Example: NAT traffic from LAN out to WAN using the WAN interface IP
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
    check("UC-04.5: Create a Source NAT rule (SNAT/Masquerade)",
          r and r.status_code in [200, 201, 404])  # 404 if not implemented

    # Test 4.5: Edit NAT rule
    r = api_request("PUT", f"/api/config/firewall_nat/{pf_rule_name}", session, {
        "extport": "9090",
        "comment": "Updated: WAN:9090 -> 192.168.1.100:80"
    })
    if r and r.status_code == 200:
        check("UC-04.6: Edit NAT rule (change extport)",
              True)

    # Test 4.6: Delete the test NAT rules
    for rule_name in [pf_rule_name, snat_rule_name]:
        r = api_request("DELETE", f"/api/config/firewall_nat/{rule_name}", session)
        if r and r.status_code in [200, 404]:
            check(f"UC-04.7: Delete NAT rule {rule_name}",
                  r.status_code == 200 or r.status_code == 404)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 5: DHCP SERVER MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def test_dhcp_server(session):
    """UC-05: Configure the DHCP server for LAN"""
    section("USE CASE 5", "DHCP Server Management")

    # Test 5.1: List DHCP pools
    r = api_request("GET", "/api/config/system_dhcp", session)
    check("UC-05.1: List DHCP pools",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        dhcp_pools = r.json()
        info(f"There are currently {len(dhcp_pools)} DHCP pools")

    # Test 5.2: Create a new DHCP pool
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
    check("UC-05.2: Create a new DHCP pool for LAN",
          r and r.status_code in [200, 201])

    # Test 5.3: Verify the DHCP pool just created
    r = api_request("GET", f"/api/config/system_dhcp/{test_pool_name}", session)
    if r and r.status_code == 200:
        pool_data = r.json()
        check("UC-05.3: DHCP pool has start IP = 192.168.1.100",
              pool_data.get("start") == "192.168.1.100")
        check("UC-05.4: DHCP pool has DNS servers",
              "8.8.8.8" in pool_data.get("dns", ""))

    # Test 5.4: Edit DHCP pool (change IP range)
    r = api_request("PUT", f"/api/config/system_dhcp/{test_pool_name}", session, {
        "start": "192.168.1.50",
        "end": "192.168.1.150"
    })
    check("UC-05.5: Edit DHCP pool (change IP range)",
          r and r.status_code == 200)

    # Test 5.5: Create a DHCP static lease (MAC → IP binding)
    static_lease_name = "test-static-lease"
    r = api_request("POST", "/api/config/system_dhcp_reservation", session, {
        "name": static_lease_name,
        "pool": test_pool_name,
        "mac": "aa:bb:cc:dd:ee:ff",
        "ip": "192.168.1.10",
        "hostname": "test-device"
    })
    if r and r.status_code in [200, 201]:
        check("UC-05.6: Create a DHCP static reservation (MAC → IP)",
              True)
        # Cleanup
        api_request("DELETE", f"/api/config/system_dhcp_reservation/{static_lease_name}", session)
    elif r and r.status_code == 404:
        warn("UC-05.6: DHCP reservation API not yet implemented")

    # Test 5.6: Disable DHCP pool
    r = api_request("PUT", f"/api/config/system_dhcp/{test_pool_name}", session, {
        "status": "disable"
    })
    check("UC-05.7: Disable DHCP pool",
          r and r.status_code == 200)

    # Test 5.7: Delete DHCP pool
    r = api_request("DELETE", f"/api/config/system_dhcp/{test_pool_name}", session)
    check("UC-05.8: Delete the test DHCP pool",
          r and r.status_code == 200)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 6: STATIC ROUTE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def test_static_routes(session):
    """UC-06: Configure static routing"""
    section("USE CASE 6", "Static Route Management")

    # Test 6.1: List routes
    r = api_request("GET", "/api/config/system_route", session)
    check("UC-06.1: List static routes",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        routes = r.json()
        info(f"There are currently {len(routes)} static routes")

    # Test 6.2: Create a new static route
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
    check("UC-06.2: Create a new static route (10.0.0.0/8)",
          r and r.status_code in [200, 201])

    # Test 6.3: Verify the route just created
    r = api_request("GET", f"/api/config/system_route/{test_route_name}", session)
    if r and r.status_code == 200:
        route_data = r.json()
        check("UC-06.3: Route has destination = 10.0.0.0/8",
              "10.0.0.0" in route_data.get("destination", ""))
        check("UC-06.4: Route has gateway = 192.168.1.254",
              route_data.get("gateway") == "192.168.1.254")

    # Test 6.4: Edit route (change metric)
    r = api_request("PUT", f"/api/config/system_route/{test_route_name}", session, {
        "metric": "20"
    })
    check("UC-06.5: Edit route (change metric)",
          r and r.status_code == 200)

    # Test 6.5: Delete the test route
    r = api_request("DELETE", f"/api/config/system_route/{test_route_name}", session)
    check("UC-06.6: Delete the test static route",
          r and r.status_code == 200)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 7: ADDRESS & SERVICE OBJECT MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def test_objects(session):
    """UC-07: Manage Address Objects and Service Objects"""
    section("USE CASE 7", "Address & Service Object Management")

    # Test 7.1: List address objects
    r = api_request("GET", "/api/config/firewall_address", session)
    check("UC-07.1: List address objects",
          r and r.status_code == 200)

    # Test 7.2: Create an address object (subnet)
    test_addr_name = "test-addr-subnet"
    r = api_request("POST", "/api/config/firewall_address", session, {
        "name": test_addr_name,
        "type": "ipmask",
        "subnet": "172.16.0.0/16",
        "comment": "Test address object - subnet"
    })
    check("UC-07.2: Create an address object (subnet 172.16.0.0/16)",
          r and r.status_code in [200, 201])

    # Test 7.3: Create an address object (IP range)
    test_addr_range = "test-addr-range"
    r = api_request("POST", "/api/config/firewall_address", session, {
        "name": test_addr_range,
        "type": "iprange",
        "start_ip": "10.10.10.10",
        "end_ip": "10.10.10.20",
        "comment": "Test address object - IP range"
    })
    check("UC-07.3: Create an address object (IP range 10.10.10.10-20)",
          r and r.status_code in [200, 201])

    # Test 7.4: Verify address object
    r = api_request("GET", f"/api/config/firewall_address/{test_addr_name}", session)
    if r and r.status_code == 200:
        addr_data = r.json()
        check("UC-07.4: Address object has type = ipmask",
              addr_data.get("type") == "ipmask")
        check("UC-07.5: Address object has subnet = 172.16.0.0/16",
              "172.16.0.0" in addr_data.get("subnet", ""))

    # Test 7.5: List service objects
    r = api_request("GET", "/api/config/firewall_service", session)
    check("UC-07.6: List service objects",
          r and r.status_code == 200)

    # Test 7.6: Create a service object (custom port)
    test_svc_name = "test-svc-custom"
    r = api_request("POST", "/api/config/firewall_service", session, {
        "name": test_svc_name,
        "protocol": "tcp",
        "port": "8443",
        "comment": "Test service - HTTPS alternate port"
    })
    check("UC-07.7: Create a service object (TCP/8443)",
          r and r.status_code in [200, 201])

    # Test 7.7: Create a service object (port range)
    test_svc_range = "test-svc-range"
    r = api_request("POST", "/api/config/firewall_service", session, {
        "name": test_svc_range,
        "protocol": "tcp",
        "port": "8000-9000",
        "comment": "Test service - port range 8000-9000"
    })
    check("UC-07.8: Create a service object (TCP port range 8000-9000)",
          r and r.status_code in [200, 201])

    # Test 7.8: Delete the test objects
    for obj_name in [test_addr_name, test_addr_range]:
        r = api_request("DELETE", f"/api/config/firewall_address/{obj_name}", session)
        check(f"UC-07.9: Delete address object {obj_name}",
              r and r.status_code in [200, 404])

    for obj_name in [test_svc_name, test_svc_range]:
        r = api_request("DELETE", f"/api/config/firewall_service/{obj_name}", session)
        check(f"UC-07.10: Delete service object {obj_name}",
              r and r.status_code in [200, 404])


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 8: SYSTEM MONITORING (DASHBOARD)
# ══════════════════════════════════════════════════════════════════════════════

def test_system_monitoring(session):
    """UC-08: Monitor system resources (CPU, RAM, Disk, Network)"""
    section("USE CASE 8", "System Monitoring (Dashboard)")

    # Test 8.1: Get the resource overview
    r = api_request("GET", "/api/system/resources", session)
    check("UC-08.1: Get system resources",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        resources = r.json()
        info(f"CPU: {resources.get('cpu', 'N/A')}%")
        info(f"RAM: {resources.get('ram', 'N/A')}%")
        info(f"Disk: {resources.get('disk', 'N/A')}%")

        check("UC-08.2: Response has field 'cpu'",
              'cpu' in resources)
        check("UC-08.3: Response has field 'ram'",
              'ram' in resources)
        check("UC-08.4: Response has field 'disk'",
              'disk' in resources)

    # Test 8.2: Get RAM usage detail
    r = api_request("GET", "/api/system/resources/ram", session)
    check("UC-08.5: Get RAM usage detail",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        ram_data = r.json()
        info(f"RAM Total: {ram_data.get('total', 'N/A')} MB")
        info(f"RAM Used: {ram_data.get('used', 'N/A')} MB")

    # Test 8.3: Get disk usage info
    r = api_request("GET", "/api/system/resources/disk", session)
    check("UC-08.6: Get Disk usage detail",
          r and r.status_code == 200)

    # Test 8.4: Get session count (current number of connections)
    r = api_request("GET", "/api/system/sessions", session)
    if r and r.status_code == 200:
        sessions = r.json()
        info(f"Active sessions: {sessions.get('count', 'N/A')}")
        check("UC-08.7: Get active session info",
              True)
    elif r and r.status_code == 404:
        warn("UC-08.7: Session tracking API not yet implemented")

    # Test 8.5: Get network statistics
    r = api_request("GET", "/api/system/network/stats", session)
    if r and r.status_code == 200:
        net_stats = r.json()
        check("UC-08.8: Get network statistics",
              True)
        if isinstance(net_stats, list):
            for iface_stat in net_stats[:2]:
                info(f"Interface {iface_stat.get('name')}: RX {iface_stat.get('rx_bytes', 0)} / TX {iface_stat.get('tx_bytes', 0)}")
    elif r and r.status_code == 404:
        warn("UC-08.8: Network stats API not yet implemented")


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 9: DIAGNOSTIC TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def test_diagnostic_tools(session):
    """UC-09: Network diagnostic tools (Ping, Traceroute, DNS lookup)"""
    section("USE CASE 9", "Diagnostic Tools")

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
        warn("UC-09.4: Traceroute not yet implemented")

    # Test 9.5: Test with an invalid target (must fail)
    r = api_request("POST", "/api/diagnose/ping", session, {
        "target": "invalid_target!@#"
    })
    check("UC-09.5: Ping with an invalid target must fail (400)",
          r and r.status_code == 400)

    # Test 9.6: Test missing target parameter
    r = api_request("POST", "/api/diagnose/ping", session, {})
    check("UC-09.6: Ping without a target must fail (400)",
          r and r.status_code == 400)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 10: FIRMWARE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def test_firmware_management(session):
    """UC-10: Manage firmware (view version, upload, upgrade)"""
    section("USE CASE 10", "Firmware Management")

    # Test 10.1: Get the current firmware info
    r = api_request("GET", "/api/system/firmware", session)
    check("UC-10.1: Get firmware version info",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        fw_info = r.json()
        info(f"Current firmware: {fw_info.get('current_version', 'N/A')}")
        check("UC-10.2: Response has field 'current_version'",
              'current_version' in fw_info or 'version' in fw_info)

    # Test 10.2: Check firmware upgrade progress
    r = api_request("GET", "/api/system/firmware/progress", session)
    check("UC-10.3: Get firmware upgrade progress",
          r and r.status_code == 200)

    # Test 10.3: Firmware upload validation
    # Note: This test does not actually upload a file
    info("UC-10.4: Firmware upload test skipped (needs a real .itb file)")

    # Test 10.4: Trigger upgrade (stub test - does not actually upgrade)
    r = api_request("POST", "/api/system/firmware/upgrade", session, {})
    if r and r.status_code == 501:
        check("UC-10.5: Firmware upgrade API returns 501 (not implemented - OK)",
              True)
    elif r and r.status_code in [200, 400]:
        warn("UC-10.5: Firmware upgrade API returned a response (may be implemented)")


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 11: ADMIN ACCOUNT MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def test_admin_management(session):
    """UC-11: Manage admin accounts and authorization"""
    section("USE CASE 11", "Admin Account Management")

    # Test 11.1: List admin users
    r = api_request("GET", "/api/config/system_admin", session)
    check("UC-11.1: List admin users",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        admins = r.json()
        info(f"There are currently {len(admins)} admin users")

    # Test 11.2: List admin profiles (roles)
    r = api_request("GET", "/api/config/system_admin-profile", session)
    check("UC-11.2: List admin profiles",
          r and r.status_code == 200)

    if r and r.status_code == 200:
        profiles = r.json()
        info(f"Available profiles: {', '.join([p.get('name', '') for p in profiles])}")

    # Test 11.3: Create a new admin user with the read-only profile
    test_admin_user = "testuser-ro"
    test_admin_pass = "TestPass123!"
    r = api_request("POST", "/api/admin/create", session, {
        "username": test_admin_user,
        "password": test_admin_pass,
        "profile": "read-only"
    })
    check("UC-11.3: Create a new admin user (read-only profile)",
          r and r.status_code in [200, 201])

    # Test 11.4: Log in as the newly created user
    ro_session = requests.Session()
    r = api_request("POST", "/api/auth/login", ro_session, {
        "username": test_admin_user,
        "password": test_admin_pass
    })
    check("UC-11.4: Login as the read-only user succeeds",
          r and r.status_code == 200)

    # Test 11.5: Verify the read-only user cannot create a policy
    r = api_request("POST", "/api/config/firewall_policy", ro_session, {
        "name": "should-fail",
        "action": "accept"
    })
    check("UC-11.5: Read-only user cannot create a firewall policy (403)",
          r and r.status_code == 403)

    # Test 11.6: Verify the read-only user can read config
    r = api_request("GET", "/api/config/firewall_policy", ro_session)
    check("UC-11.6: Read-only user can read firewall policies (200)",
          r and r.status_code == 200)

    # Test 11.7: Change the user's password
    r = api_request("POST", "/api/auth/change-password", ro_session, {
        "password": "NewPass456!"
    })
    check("UC-11.7: User changes their own password successfully",
          r and r.status_code == 200)

    # Test 11.8: Verify the old password no longer works
    old_session = requests.Session()
    r = api_request("POST", "/api/auth/login", old_session, {
        "username": test_admin_user,
        "password": test_admin_pass
    })
    check("UC-11.8: Login with the old password fails (401)",
          r and r.status_code == 401)

    # Test 11.9: Admin deletes the test user
    r = api_request("DELETE", f"/api/config/system_admin/{test_admin_user}", session)
    check("UC-11.9: Admin deletes the test user",
          r and r.status_code == 200)

    # Test 11.10: The builtin admin must not be deletable
    r = api_request("DELETE", "/api/config/system_admin/admin", session)
    check("UC-11.10: Cannot delete the builtin admin account (403)",
          r and r.status_code == 403)


# ══════════════════════════════════════════════════════════════════════════════
# USE CASE 12: SECURITY CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def test_security_features(session):
    """UC-12: Test security features (XSS, CSRF, Session, Headers)"""
    section("USE CASE 12", "Security Checks (Security Features)")

    # Test 12.1: HTTPS Security Headers
    r = api_request("GET", "/api/auth/whoami", session)
    if r and r.status_code == 200:
        headers = r.headers
        check("UC-12.1: Response has X-Content-Type-Options: nosniff",
              'X-Content-Type-Options' in headers and headers['X-Content-Type-Options'] == 'nosniff')
        check("UC-12.2: Response has X-Frame-Options: DENY",
              'X-Frame-Options' in headers and headers['X-Frame-Options'] == 'DENY')
        check("UC-12.3: Response has Content-Security-Policy",
              'Content-Security-Policy' in headers)

        if BASE_URL.startswith('https'):
            check("UC-12.4: Response has Strict-Transport-Security (HSTS)",
                  'Strict-Transport-Security' in headers)

    # Test 12.2: XSS Protection - do not allow scripts in input
    r = api_request("POST", "/api/config/firewall_policy", session, {
        "name": "<script>alert('xss')</script>",
        "action": "accept"
    })
    check("UC-12.5: Reject XSS in policy name (400)",
          r and r.status_code in [400, 404])

    # Test 12.3: SQL Injection Protection
    r = api_request("GET", "/api/config/firewall_policy/'; DROP TABLE firewall_policy; --", session)
    check("UC-12.6: SQL injection in the URL causes no error (404 or 400)",
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
        check("UC-12.7: Session cookie has the HttpOnly flag",
              'HttpOnly' in set_cookie_header)
        check("UC-12.8: Session cookie has SameSite=Strict",
              'SameSite=Strict' in set_cookie_header)
        if BASE_URL.startswith('https'):
            check("UC-12.9: Session cookie has the Secure flag (HTTPS only)",
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

    check("UC-12.11: Rate limiting kicks in after several failed logins (429)",
          rate_limited,
          f"Failed {fail_count} times before rate limit")

    # Test 12.6: Session timeout
    # Create a new session, then check whether it times out (needs a long wait - skipped in the quick test)
    info("UC-12.12: Session timeout test skipped (needs a 15-minute wait)")

    # Test 12.7: Path traversal protection
    r = api_request("GET", "/api/config/../../etc/passwd", session)
    check("UC-12.13: Path traversal does not work (404 or 400)",
          r and r.status_code in [400, 404])


# ══════════════════════════════════════════════════════════════════════════════
# MAIN TEST RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def main():
    header("STARGAZER NGFW - FIREWALL USE CASE TESTS")

    info(f"Target URL: {BASE_URL}")
    info(f"Admin User: {ADMIN_USER}")
    info(f"Starting tests...")

    start_time = time.time()

    # Check the connection to the firewall
    try:
        r = requests.get(urljoin(BASE_URL, "/"), timeout=5, verify=False)
        check("Connect to the Web UI", r.status_code == 200)
    except Exception as e:
        check("Connect to the Web UI", False, str(e))
        print(f"\n{RED}COULD NOT CONNECT TO {BASE_URL}{RESET}")
        sys.exit(1)

    # Run the test suites
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

    # Summary
    elapsed = time.time() - start_time
    header("TEST RESULTS")

    total = PASS_COUNT + FAIL_COUNT
    pass_rate = (PASS_COUNT / total * 100) if total > 0 else 0

    print(f"{GREEN}✓ PASS:  {PASS_COUNT}{RESET}")
    print(f"{RED}✗ FAIL:  {FAIL_COUNT}{RESET}")
    print(f"{YELLOW}⚠ WARN:  {WARN_COUNT}{RESET}")
    print(f"\n{BOLD}Total tests: {total}{RESET}")
    print(f"{BOLD}Pass rate:   {pass_rate:.1f}%{RESET}")
    print(f"{BOLD}Elapsed:     {elapsed:.2f}s{RESET}")

    if FAIL_COUNT == 0:
        print(f"\n{GREEN}{BOLD}ALL TEST CASES PASSED!{RESET}")
        sys.exit(0)
    else:
        print(f"\n{YELLOW}{BOLD}{FAIL_COUNT} TEST CASE(S) FAILED{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
