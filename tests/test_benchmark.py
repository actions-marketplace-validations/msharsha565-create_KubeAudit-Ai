import time
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_admission_webhook_latency_under_50ms():
    payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "bench-uid-1234",
            "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
            "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
            "namespace": "default",
            "operation": "CREATE",
            "object": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "bench-api", "namespace": "default"},
                "spec": {
                    "template": {
                        "spec": {
                            "securityContext": {"runAsNonRoot": True},
                            "containers": [
                                {
                                    "name": "web",
                                    "image": "nginx:alpine",
                                    "securityContext": {
                                        "privileged": False,
                                        "readOnlyRootFilesystem": True,
                                        "allowPrivilegeEscalation": False
                                    },
                                    "resources": {
                                        "limits": {"cpu": "500m", "memory": "512Mi"},
                                        "requests": {"cpu": "100m", "memory": "128Mi"}
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    latencies = []
    # Warm-up run
    client.post("/validate", json=payload)

    # 50 iterations measurement
    for _ in range(50):
        start = time.perf_counter()
        resp = client.post("/validate", json=payload)
        latencies.append((time.perf_counter() - start) * 1000)
        assert resp.status_code == 200

    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
    print(f"\nAdmission Latency P95: {p95_latency:.2f}ms | Avg: {sum(latencies)/len(latencies):.2f}ms")
    assert p95_latency < 50.0, f"P95 latency {p95_latency}ms exceeded 50ms threshold"
