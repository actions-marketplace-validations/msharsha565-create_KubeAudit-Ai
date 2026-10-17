#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="kubeaudit"
SERVICE="kubeaudit-service"
CERT_DIR="$(mktemp -d)"

echo "==> Generating CA and Server Certificates for ${SERVICE}.${NAMESPACE}.svc..."

# 1. Generate Root CA
openssl req -nodes -new -x509 -keyout "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" -subj "/CN=KubeAudit-CA" -days 365

# 2. Generate Server Key & CSR
openssl req -nodes -new -keyout "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" -subj "/CN=${SERVICE}.${NAMESPACE}.svc"

# 3. Create SAN Extension Configuration
cat <<CONF > "${CERT_DIR}/csr.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVICE}
DNS.2 = ${SERVICE}.${NAMESPACE}
DNS.3 = ${SERVICE}.${NAMESPACE}.svc
DNS.4 = ${SERVICE}.${NAMESPACE}.svc.cluster.local
CONF

# 4. Sign the Server Certificate
openssl x509 -req -in "${CERT_DIR}/server.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
  -out "${CERT_DIR}/server.crt" -days 365 -extfile "${CERT_DIR}/csr.ext"

# 5. Output base64 encoded strings
CA_BUNDLE=$(base64 < "${CERT_DIR}/ca.crt" | tr -d '\n')
SERVER_CRT=$(base64 < "${CERT_DIR}/server.crt" | tr -d '\n')
SERVER_KEY=$(base64 < "${CERT_DIR}/server.key" | tr -d '\n')

echo "==> Writing deploy/tls-secret.yaml..."
cat <<SECRET_MANIFEST > deploy/tls-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: kubeaudit-tls
  namespace: ${NAMESPACE}
type: kubernetes.io/tls
data:
  tls.crt: ${SERVER_CRT}
  tls.key: ${SERVER_KEY}
SECRET_MANIFEST

echo "==> Updating deploy/webhook-config.yaml with caBundle..."
sed -i "s|caBundle: .*|caBundle: ${CA_BUNDLE}|g" deploy/webhook-config.yaml 2>/dev/null || true

echo "Done. Certificates generated successfully."
rm -rf "${CERT_DIR}"
