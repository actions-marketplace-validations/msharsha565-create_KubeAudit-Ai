# KubeAudit AI

[![CI Pipeline](https://github.com/msharsha565-create/KubeAudit-Ai/actions/workflows/ci.yml/badge.svg)](https://github.com/msharsha565-create/KubeAudit-Ai/actions/workflows/ci.yml)

A lightweight, automated Kubernetes manifest security auditing and remediation service built with FastAPI, PyYAML, and Pydantic.

---

## Features

- **Security Enforcement**: Validates Kubernetes workloads against core Pod Security Standards:
  - Explicit namespace definitions
  - Enforced `runAsNonRoot: true`
  - Immutable image tagging (disallows `:latest` or omitted tags)
  - Explicit CPU and memory resource limits and requests
  - Disallows `privileged: true`
  - Enforces `readOnlyRootFilesystem: true`
  - Disallows `allowPrivilegeEscalation: true`
- **Comprehensive Coverage**: Audits `containers`, `initContainers`, and `ephemeralContainers` across Pods, Deployments, StatefulSets, DaemonSets, and Jobs.
- **Automated Remediation**: The `/fix` endpoint patches insecure manifests into compliant YAML representations.
- **Production Hardened**: Containerized using a multi-stage Dockerfile running as non-root UID `10001`.

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Redirects directly to `/docs` Swagger UI |
| `GET` | `/health` | Health check endpoint (`{"status": "ok"}`) |
| `POST` | `/audit` | Inspects manifest and returns detected security violations |
| `POST` | `/fix` | Injects security controls and returns remediated manifest |

---

## Local Development

### 1. Setup Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest httpx