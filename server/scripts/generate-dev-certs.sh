#!/bin/bash
# Generate development mTLS certificates for testing
# DO NOT USE IN PRODUCTION
#
# The agent's TLS client (rustls) is strict where openssl's defaults are not: it needs
# X.509 v3 certificates, a CA with basicConstraints CA:TRUE, and a server certificate whose
# name is in subjectAltName (a CN alone is refused). So every certificate here is v3 with
# explicit extensions, and the server certificate names `localhost`, 127.0.0.1 and ::1.
# To reach the control plane by another name or address, list it, for example:
#
#   DEV_CERT_SANS="DNS:cp.lab,IP:192.168.122.1" bash scripts/generate-dev-certs.sh
#
# The agent then needs the CA, since it trusts only public roots by default (#658):
#   agent apply-release --ca-cert certs/ca.crt ...   (or `server.ca_cert` in agent.toml)

set -e

CERTS_DIR="certs"
SANS="DNS:localhost,IP:127.0.0.1,IP:::1${DEV_CERT_SANS:+,$DEV_CERT_SANS}"
mkdir -p $CERTS_DIR

echo "==> Generating CA certificate..."
openssl req -new -x509 -days 3650 -nodes \
  -out $CERTS_DIR/ca.crt \
  -keyout $CERTS_DIR/ca.key \
  -subj "/C=US/ST=Dev/L=Dev/O=Synthaea/OU=Dev/CN=Synthaea Dev CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "==> Generating server certificate ($SANS)..."
openssl req -new -nodes \
  -out $CERTS_DIR/server.csr \
  -keyout $CERTS_DIR/server.key \
  -subj "/C=US/ST=Dev/L=Dev/O=Synthaea/OU=Dev/CN=localhost"

printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$SANS" \
  > $CERTS_DIR/server.ext

openssl x509 -req -days 3650 \
  -in $CERTS_DIR/server.csr \
  -CA $CERTS_DIR/ca.crt \
  -CAkey $CERTS_DIR/ca.key \
  -CAcreateserial \
  -extfile $CERTS_DIR/server.ext \
  -out $CERTS_DIR/server.crt

echo "==> Generating test agent certificate..."
openssl req -new -nodes \
  -out $CERTS_DIR/agent-test.csr \
  -keyout $CERTS_DIR/agent-test.key \
  -subj "/C=US/ST=Dev/L=Dev/O=Synthaea/OU=Agents/CN=agent-test-001"

printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' \
  > $CERTS_DIR/agent-test.ext

openssl x509 -req -days 3650 \
  -in $CERTS_DIR/agent-test.csr \
  -CA $CERTS_DIR/ca.crt \
  -CAkey $CERTS_DIR/ca.key \
  -CAcreateserial \
  -extfile $CERTS_DIR/agent-test.ext \
  -out $CERTS_DIR/agent-test.crt

rm $CERTS_DIR/*.csr $CERTS_DIR/*.ext

echo "==> Certificates generated in $CERTS_DIR/"
echo "    ca.crt/key - CA certificate and key"
echo "    server.crt/key - Server certificate for nginx"
echo "    agent-test.crt/key - Test agent client certificate"
