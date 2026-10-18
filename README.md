# KubeAudit AI

KubeAudit AI is an automated Kubernetes manifest security auditor and admission webhook engine built with FastAPI, cert-manager, and Helm. It inspects resource manifests for security misconfigurations, auto-remediates insecure workloads via RFC 6902 JSON Patches, and enforces admission compliance directly within the cluster.

---

## Architecture Overview

* **FastAPI Core (`app/main.py`)**: Implements `/audit`, `/fix`, `/validate`, and `/mutate` endpoints.
* **Automated TLS (`cert-manager`*)*: Issues self-signed cluster certificates and leverages `cert-manager.io/inject-ca-from` to populate the admission webhook `caBundle`$ynamically.
* **Self-Healing Webhook**:
  * **Validating Webhook**: Intercepts admission requests and denies non-compliant deployments (`runAsNonRoot: false`, privileged containers, missing resource limits).
  * **Mutating Webhook**: Transparently patches insecure manifests during creation (pins `:alpine` tags, injects non-root security contexts, and applies default CPU/memory limits).
* **Helm Packaging (`charts/kubeaudit-ai`*)*: Complete Helm v2 deployment with automated `helm test` health verification.

---

## Local Development & Cluster Setup

### Prerequisites
* Docker
* `kind` (Kubernetes in Docker)
* `kubectl`
* `helm` (v3+)

### 1. Build Application Image
To ensure compatibility with containerd CRI in `kind`, disable BuildKit provenance attestations:
```bash
docker build --provenance=false -t kubeaudit-ai:latest .
```

### 2. Sideload Images into Kind
```bash
for img in \
  quay.io/jetstack/cert-manager-controller:v1.16.1 \
  quay.io/jetstack/cert-manager-cainjector:v1.16.1 \
  quay.io/jetstack/cert-manager-webhook:v1.16.1 \
  kubeaudit-ai:latest; do
    docker save "$img" | docker exec -i kubeaudit-test-control-plane ctr -n k8s.io images import -
done
```

### 3. Deploy cert-manager
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.1/cert-manager.yaml
kubectl wait --namespace cert-manager --for_condition=ready pod --all --timeout=90s
```

### 4. Deploy KubeAudit AI via Helm
```bash
helm upgrade --install kubeaudit charts/kubeaudit-ai/ \
  --namespace kubeaudit \
  --create-namespace

kubectl wait --namespace kubeaudit \
  --for=condition=ready pod \
  --selector=app=kubeaudit \
  --timeout=60s
```

---

## Verification & Testing

### Run Automated In-Cluster Helm Test
```bash
helm test kubeaudit -n kubeaudit --timeout 60s
```

### Verify Dynamic Manifest Mutation
Deploy an unpatched, insecure manifest:
```bash
kubectl apply -f manifests/sample-deployment.yaml
```

Verify that the mutating webhook auto-injected security constraints:
```bash
# Verify container image pinned:
kubectl get deployment demo-api -n default -o jsonpath='{.spec.template.spec.containers[0].image}'

# Verify non-root enforcement:
kubectl get deployment demo-api -n default -o jsonpath='{.spec.template.spec.securityContext.runAsNonRoot}'

# Verify resource limits injected:
kubectl get deployment demo-api -n default -o jsonpath='{.spec.template.spec.containers[0].resources}'
```
