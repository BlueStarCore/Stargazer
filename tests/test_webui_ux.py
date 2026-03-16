#!/usr/bin/env python3
"""
test_webui_ux.py — UI experience verification

Verifies that forms, tables, labels, and columns are all consistent
so the user doesn't see broken layouts, mismatched data, or orphaned fields.

Run: python3 tests/test_webui_ux.py
"""

import os
import re
import sys

PASS = 0
FAIL = 0
TOTAL = 0

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def check(name, condition, detail=""):
    global PASS, FAIL, TOTAL
    TOTAL += 1
    if condition:
        PASS += 1
        print(f"  {GREEN}PASS{RESET} {name}")
    else:
        FAIL += 1
        print(f"  {RED}FAIL{RESET} {name}")
        if detail:
            print(f"       {detail}")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

html = open(os.path.join(BASE, "src/userspace/webui/www/home.html")).read()
appjs = open(os.path.join(BASE, "src/userspace/webui/www/js/app.js")).read()
loginjs = open(os.path.join(BASE, "src/userspace/webui/www/js/login.js")).read()


def extract_form_labels(html_content, form_id):
    """Extract form-label text from a modal form."""
    # Find the form by id
    pattern = rf'id="{form_id}".*?</div>\s*<div class="modal-footer">'
    m = re.search(pattern, html_content, re.DOTALL)
    if not m:
        return []
    form_html = m.group(0)
    labels = re.findall(r'<label class="form-label">([^<]+)</label>', form_html)
    return labels


def extract_entity_fields(js_content, entity_name):
    """Extract fields array from ENTITIES definition."""
    # Find the entity block
    pattern = rf'{entity_name}:\s*\{{.*?fields:\s*\[(.*?)\]'
    m = re.search(pattern, js_content, re.DOTALL)
    if not m:
        return []
    fields_str = m.group(1)
    fields = []
    for fm in re.finditer(r"\{([^}]+)\}", fields_str):
        field_str = fm.group(1)
        label_m = re.search(r"label:\s*'([^']+)'", field_str)
        key_m = re.search(r"key:\s*'([^']+)'", field_str)
        col_m = re.search(r"col:\s*(-?\d+)", field_str)
        if label_m and key_m and col_m:
            fields.append({
                'label': label_m.group(1),
                'key': key_m.group(1),
                'col': int(col_m.group(1))
            })
    return fields


def extract_thead_columns(html_content, entity_or_id):
    """Extract column names from a table's thead."""
    # Try data-entity first
    pattern = rf'data-entity="{entity_or_id}".*?<thead><tr>(.*?)</tr></thead>'
    m = re.search(pattern, html_content, re.DOTALL)
    if not m:
        # Try by id
        pattern = rf'id="{entity_or_id}".*?<thead>.*?<tr>(.*?)</tr>'
        m = re.search(pattern, html_content, re.DOTALL)
    if not m:
        return []
    header_html = m.group(1)
    # Split on </th> to get each column
    parts = header_html.split('</th>')
    clean_cols = []
    for part in parts:
        # Extract text content, removing all tags
        text = re.sub(r'<[^>]+>', '', part).strip()
        if text and 'checkbox' not in part.lower() and 'select-all' not in part.lower():
            clean_cols.append(text)
    return clean_cols


# ================================================================
# TEST: Interface config page
# ================================================================
print(f"\n{BOLD}=== Interfaces Config Page ==={RESET}")

iface_form_labels = extract_form_labels(html, 'form-iface')
iface_fields = extract_entity_fields(appjs, 'interfaces')
iface_cols = extract_thead_columns(html, 'interfaces')

print(f"  Form labels: {iface_form_labels}")
print(f"  Entity fields: {[(f['label'], f['col']) for f in iface_fields]}")
print(f"  Table columns: {iface_cols}")

# Table column count should match fields with col >= 0
table_fields = [f for f in iface_fields if f['col'] >= 0]
check("Interface: table columns = entity fields with col>=0",
      len(iface_cols) == len(table_fields),
      f"Table has {len(iface_cols)} cols, entity has {len(table_fields)} visible fields")

# Every form label should have a matching entity field label
for label in iface_form_labels:
    has_match = any(f['label'].lower() == label.lower() for f in iface_fields)
    check(f"Interface form label '{label}' has entity field",
          has_match)

# No "Alias" or "Type" in table columns
check("Interface: no ALIAS column in table",
      'ALIAS' not in [c.upper() for c in iface_cols])
check("Interface: no TYPE column in table",
      'TYPE' not in [c.upper() for c in iface_cols])
check("Interface: has MODE column in table",
      'MODE' in [c.upper() for c in iface_cols])


# ================================================================
# TEST: DHCP config page
# ================================================================
print(f"\n{BOLD}=== DHCP Config Page ==={RESET}")

dhcp_form_labels = extract_form_labels(html, 'form-dhcp')
dhcp_fields = extract_entity_fields(appjs, 'dhcp')
dhcp_cols = extract_thead_columns(html, 'dhcp')

print(f"  Form labels: {dhcp_form_labels}")
print(f"  Entity fields: {[(f['label'], f['col']) for f in dhcp_fields]}")
print(f"  Table columns: {dhcp_cols}")

# Table column count should match fields with col >= 0
dhcp_table_fields = [f for f in dhcp_fields if f['col'] >= 0]
check("DHCP: table columns = entity fields with col>=0",
      len(dhcp_cols) == len(dhcp_table_fields),
      f"Table has {len(dhcp_cols)} cols, entity has {len(dhcp_table_fields)} visible fields")

# Form-only fields should not be in table columns
form_only = [f['label'] for f in dhcp_fields if f['col'] == -1]
for label in form_only:
    check(f"DHCP: form-only '{label}' NOT in table columns",
          label.upper() not in [c.upper() for c in dhcp_cols])

# No orphan LEASES column
check("DHCP: no orphan LEASES column in table",
      'LEASES' not in [c.upper() for c in dhcp_cols])

# All form labels match entity fields
for label in dhcp_form_labels:
    has_match = any(f['label'].lower() == label.lower() for f in dhcp_fields)
    check(f"DHCP form label '{label}' has entity field",
          has_match)


# ================================================================
# TEST: Routes config page
# ================================================================
print(f"\n{BOLD}=== Routes Config Page ==={RESET}")

route_form_labels = extract_form_labels(html, 'form-route')
route_fields = extract_entity_fields(appjs, 'routes')
route_cols = extract_thead_columns(html, 'routes')

print(f"  Form labels: {route_form_labels}")
print(f"  Entity fields: {[(f['label'], f['col']) for f in route_fields]}")
print(f"  Table columns: {route_cols}")

route_table_fields = [f for f in route_fields if f['col'] >= 0]
check("Routes: table columns = entity fields with col>=0",
      len(route_cols) == len(route_table_fields),
      f"Table has {len(route_cols)} cols, entity has {len(route_table_fields)} visible fields")

for label in route_form_labels:
    has_match = any(f['label'].lower() == label.lower() for f in route_fields)
    check(f"Routes form label '{label}' has entity field",
          has_match)


# ================================================================
# TEST: NAT config page
# ================================================================
print(f"\n{BOLD}=== NAT Config Page ==={RESET}")

nat_form_labels = extract_form_labels(html, 'form-nat')
nat_fields = extract_entity_fields(appjs, 'nat')
nat_cols = extract_thead_columns(html, 'nat')

print(f"  Form labels: {nat_form_labels}")
print(f"  Entity fields: {[(f['label'], f['col']) for f in nat_fields]}")
print(f"  Table columns: {nat_cols}")

nat_table_fields = [f for f in nat_fields if f['col'] >= 0]
check("NAT: table columns = entity fields with col>=0",
      len(nat_cols) == len(nat_table_fields),
      f"Table has {len(nat_cols)} cols, entity has {len(nat_table_fields)} visible fields")

for label in nat_form_labels:
    has_match = any(f['label'].lower() == label.lower() for f in nat_fields)
    check(f"NAT form label '{label}' has entity field",
          has_match)

# Form-only NAT fields exist
check("NAT: Translated Address field in entity (col:-1)",
      any(f['label'] == 'Translated Address' and f['col'] == -1 for f in nat_fields))
check("NAT: Translated Port field in entity (col:-1)",
      any(f['label'] == 'Translated Port' and f['col'] == -1 for f in nat_fields))


# ================================================================
# TEST: Policies config page
# ================================================================
print(f"\n{BOLD}=== Policies Config Page ==={RESET}")

policy_form_labels = extract_form_labels(html, 'form-policy')
policy_fields = extract_entity_fields(appjs, 'policies')
policy_cols = extract_thead_columns(html, 'fw-policies')

# Note: policies table uses data-entity="policies" but page is "fw-policies"
if not policy_cols:
    policy_cols = extract_thead_columns(html, 'policies')

print(f"  Form labels: {policy_form_labels}")
print(f"  Entity fields: {[(f['label'], f['col']) for f in policy_fields]}")
print(f"  Table columns: {policy_cols}")

policy_table_fields = [f for f in policy_fields if f['col'] >= 0]
check("Policies: table columns = entity fields with col>=0",
      len(policy_cols) == len(policy_table_fields),
      f"Table has {len(policy_cols)} cols, entity has {len(policy_table_fields)} visible fields")

for label in policy_form_labels:
    has_match = any(f['label'].lower() == label.lower() for f in policy_fields)
    check(f"Policies form label '{label}' has entity field",
          has_match)


# ================================================================
# TEST: Login page UX
# ================================================================
print(f"\n{BOLD}=== Login Page UX ==={RESET}")

check("Login: error box exists",
      "login-error" in loginjs)
check("Login: shows connection error (not blank fail)",
      "CANNOT CONNECT TO MANAGEMENT DAEMON" in loginjs)
check("Login: has password change form",
      "showChangePasswordForm" in loginjs)
check("Login: password mismatch feedback",
      "PASSWORDS DO NOT MATCH" in loginjs)
check("Login: password change sends to API",
      "/api/auth/change-password" in loginjs)


# ================================================================
# TEST: Logout UX
# ================================================================
print(f"\n{BOLD}=== Logout UX ==={RESET}")

check("Logout: calls API (not just clear storage)",
      "api('/auth/logout'" in appjs)
check("Logout: redirects to login page",
      "login.html" in appjs)


# ================================================================
# TEST: Session expiry UX
# ================================================================
print(f"\n{BOLD}=== Session Expiry UX ==={RESET}")

check("Session expiry: keepalive runs every 60s",
      "KEEPALIVE_INTERVAL = 60000" in appjs)
check("Session expiry: shows toast on 401",
      "Session expired" in appjs)
check("Session expiry: redirects after delay",
      "login.html" in appjs)
check("Session expiry: detects permission changes",
      "Permissions updated" in appjs)


# ================================================================
# TEST: Firmware page UX
# ================================================================
print(f"\n{BOLD}=== Firmware Page UX ==={RESET}")

check("Firmware: shows error for wrong extension",
      "Invalid firmware file" in appjs)
check("Firmware: shows error for oversize",
      "too large" in appjs)
check("Firmware: shows upload progress",
      "Installing..." in appjs)


# ================================================================
# RESULTS
# ================================================================
print(f"\n{'='*60}")
if FAIL == 0:
    print(f"{GREEN}{BOLD}ALL {TOTAL} UX CHECKS PASSED{RESET}")
else:
    print(f"{YELLOW}Results: {GREEN}{PASS} passed{RESET}, {RED}{FAIL} failed{RESET} / {TOTAL} total")
    sys.exit(1)
