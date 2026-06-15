#!/bin/sh
# =============================================================================
# test_api_bypass.sh — Verify the firewall enforces policy guards server-side,
# even when a client bypasses the web GUI entirely and pushes raw API requests.
#
# The GUI's grey-out / drag-block / dblclick-block are UX only. This script
# ignores them: it logs in over HTTP(S), grabs the sg_sid session cookie, then
# fires the exact requests the GUI would refuse to send. Each response (HTTP
# status + JSON body) is printed so you can see how mgmtd handles it.
#
# Usage:
#   ./test_api_bypass.sh <base_url> <admin_password> [deny_id] [allow_id]
# Example:
#   ./test_api_bypass.sh https://192.168.1.1 'S3cret!'      # default ids 1 / 2
#   ./test_api_bypass.sh http://10.0.1.1:80 'S3cret!' 1 2
#
# Expected (all guards working): every attack returns an error status/body;
# only the read (GET list) succeeds.
# =============================================================================
set -u

BASE="${1:?usage: $0 <base_url> <admin_password> [deny_id] [allow_id]}"
PASS="${2:?missing admin password}"
DENY_ID="${3:-1}"      # immutable default-deny policy
ALLOW_ID="${4:-2}"     # a normal policy to try to push below default-deny
USER="${SG_USER:-admin}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# curl: -s silent, -k skip self-signed TLS verify, cookie jar for sg_sid.
CURL="curl -sk --max-time 10"

# req METHOD PATH [JSON_BODY] — print "HTTP <status>\n<body>"
req() {
	method="$1"; path="$2"; body="${3:-}"
	if [ -n "$body" ]; then
		$CURL -b "$JAR" -X "$method" "$BASE$path" \
			-H 'Content-Type: application/json' -d "$body" \
			-w '\n--- HTTP %{http_code} ---\n'
	else
		$CURL -b "$JAR" -X "$method" "$BASE$path" \
			-w '\n--- HTTP %{http_code} ---\n'
	fi
}

echo "############################################################"
echo "# Target : $BASE   (user=$USER, deny_id=$DENY_ID, allow_id=$ALLOW_ID)"
echo "############################################################"

echo
echo "==> [0] Login (POST /api/auth/login) — capture sg_sid cookie"
$CURL -c "$JAR" -X POST "$BASE/api/auth/login" \
	-H 'Content-Type: application/json' \
	-d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" \
	-w '\n--- HTTP %{http_code} ---\n'
if ! grep -q sg_sid "$JAR" 2>/dev/null; then
	echo "!! Login failed (no sg_sid cookie). Check URL/credentials/allowaccess."
	exit 1
fi

echo
echo "==> [1] BASELINE read — GET /api/config/firewall_policy (should succeed)"
req GET /api/config/firewall_policy

echo
echo "==> [2] ATTACK: modify the immutable default-deny (action drop -> accept)"
echo "    PUT /api/config/firewall_policy/$DENY_ID  — expect REJECT (immutable)"
req PUT "/api/config/firewall_policy/$DENY_ID" \
	'{"name":"default-deny","srcintf":"any","dstintf":"any","srcaddr":"all","dstaddr":"all","action":"accept","service":"all","schedule":"all","status":"enable","sequence":"1"}'

echo
echo "==> [3] ATTACK: forge immutable=no to un-protect, then open it"
echo "    PUT /api/config/firewall_policy/$DENY_ID  — expect REJECT (flag stripped + still immutable)"
req PUT "/api/config/firewall_policy/$DENY_ID" \
	'{"name":"default-deny","action":"accept","immutable":"no","srcaddr":"all","dstaddr":"all","srcintf":"any","dstintf":"any","service":"all","schedule":"all","status":"enable","sequence":"1"}'

echo
echo "==> [4] ATTACK: delete the immutable default-deny"
echo "    DELETE /api/config/firewall_policy/$DENY_ID  — expect REJECT (immutable)"
req DELETE "/api/config/firewall_policy/$DENY_ID"

echo
echo "==> [5] ATTACK: move a normal policy to sequence 1 (steal the catch-all slot)"
echo "    PATCH /api/config/firewall_policy/$ALLOW_ID/move {sequence:1} — expect REJECT (floor)"
req PATCH "/api/config/firewall_policy/$ALLOW_ID/move" '{"sequence":1}'

echo
echo "==> [6] ATTACK: move the default-deny itself"
echo "    PATCH /api/config/firewall_policy/$DENY_ID/move {sequence:5} — expect REJECT (immutable)"
req PATCH "/api/config/firewall_policy/$DENY_ID/move" '{"sequence":5}'

echo
echo "==> [7] CONTROL: legitimate move of a normal policy to seq 2 (should SUCCEED)"
echo "    PATCH /api/config/firewall_policy/$ALLOW_ID/move {sequence:2}"
req PATCH "/api/config/firewall_policy/$ALLOW_ID/move" '{"sequence":2}'

echo
echo "############################################################"
echo "# Done. Steps [2]-[6] must show error status (4xx) + error body."
echo "# Steps [1] and [7] should succeed (2xx)."
echo "############################################################"
