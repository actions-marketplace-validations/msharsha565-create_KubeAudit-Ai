#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="kubeaudit-test"
NODE_NAME="${CLUSTER_NAME}-control-plane"
ENDPOINT_DOMAIN="kubeaudit-ai-production.up.railway.app"
GATEWAY_IP="172.18.0.1"

echo "--> Checking socat host proxy..."
if ! sudo ss -tulpn | grep -q "${GATEWAY_IP}:443"; then
  echo "--> Starting socat listener on ${GATEWAY_IP}:443..."
  sudo nohup socat TCP-LISTEN:443,bind="${GATEWAY_IP}",fork,reuseaddr TCP:"${ENDPOINT_DOMAIN}":443 > /dev/null 2>&1 &
  sleep 1
else
  echo "--> socat already running on ${GATEWAY_IP}:443."
fi

echo "--> Updating /etc/hosts in ${NODE_NAME}..."
docker exec -u 0 "${NODE_NAME}" sed -i "/${ENDPOINT_DOMAIN}/d" /etc/hosts
docker exec -u 0 "${NODE_NAME}" sh -c "echo '${GATEWAY_IP} ${ENDPOINT_DOMAIN}' >> /etc/hosts"

echo "--> Restarting kube-apiserver to reload hosts..."
APISERVER_ID=$(docker exec "${NODE_NAME}" crictl ps --name kube-apiserver -q)
docker exec "${NODE_NAME}" crictl stop "${APISERVER_ID}" > /dev/null

echo "--> Waiting for API server to come back online..."
until kubectl cluster-info > /dev/null 2>&1; do
  sleep 2
done

echo "--> Admission controller bridge ready."
