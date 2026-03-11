#!/bin/bash
# Simple HTTPS server for firmware downloads
# Serves /srv/tftp/ on port 8443 with a self-signed cert
#
# Usage: ./run_https_server.sh [port] [directory]

set -e

PORT="${1:-8443}"
DIRECTORY="${2:-/srv/tftp}"
CERT_DIR="/tmp/https-server"
HOST_IP=$(hostname -I | awk '{print $1}')

# Generate self-signed cert if missing
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    mkdir -p "$CERT_DIR"
    echo "Generating self-signed certificate..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -days 30 -nodes \
        -subj "/CN=${HOST_IP}" 2>/dev/null
fi

echo "Serving $DIRECTORY on https://${HOST_IP}:${PORT}"
echo "Firewall download command:"
echo "  wget --no-check-certificate https://${HOST_IP}:${PORT}/<filename>"
echo ""
echo "Press Ctrl+C to stop."

python3 -c "
import http.server, ssl, os, sys

os.chdir('${DIRECTORY}')
httpd = http.server.HTTPServer(('0.0.0.0', ${PORT}),
    type('H', (http.server.SimpleHTTPRequestHandler,),
         {'__init__': lambda self, *a, **k: super(type(self), self).__init__(*a, directory='${DIRECTORY}', **k)}))

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('${CERT_DIR}/cert.pem', '${CERT_DIR}/key.pem')
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
"
