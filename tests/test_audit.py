from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_valid_manifest():
    secure_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
  containers:
  - name: app
    image: myregistry.io/app:v1.2.3
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
      requests:
        cpu: "250m"
        memory: "256Mi"
    securityContext:
      privileged: false
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
"""
    response = client.post("/audit", json={"manifest": secure_yaml})
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert len(data["issues"]) == 0

def test_invalid_yaml_syntax():
    response = client.post("/audit", json={"manifest": "key: value\n\ttab_not_allowed: 1"})
    assert response.status_code == 400

def test_non_dict_yaml():
    response = client.post("/audit", json={"manifest": "just a plain string"})
    assert response.status_code == 400
def test_remediation_present_on_failure():
    bad_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - name: test-container
    image: nginx:latest
"""
    response = client.post("/audit", json={"manifest": bad_yaml})
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert any(issue.get("remediation") is not None for issue in data["issues"])
def test_fix_endpoint_resolves_issues():
    insecure_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: fixable-pod
spec:
  containers:
  - name: web
    image: nginx:1.25.0
    securityContext:
      privileged: true
"""
    fix_response = client.post("/fix", json={"manifest": insecure_yaml})
    assert fix_response.status_code == 200
    fixed_data = fix_response.json()
    assert len(fixed_data["applied_fixes"]) > 0

    # Feed the remediated manifest back into /audit to ensure no security issues remain
    audit_response = client.post("/audit", json={"manifest": fixed_data["remediated_manifest"]})
    assert audit_response.status_code == 200
    audit_data = audit_response.json()
    assert audit_data["valid"] is True
    assert len(audit_data["issues"]) == 0
def test_validate_admission_allowed():
    admission_review_payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "705ab4f5-6393-11e8-b7cc-42010a800002",
            "object": {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": "secure-pod",
                    "namespace": "production"
                },
                "spec": {
                    "securityContext": {
                        "runAsNonRoot": True
                    },
                    "containers": [{
                        "name": "web",
                        "image": "nginx:1.25.0",
                        "resources": {
                            "limits": {"cpu": "500m", "memory": "512Mi"},
                            "requests": {"cpu": "100m", "memory": "128Mi"}
                        },
                        "securityContext": {
                            "privileged": False,
                            "readOnlyRootFilesystem": True,
                            "allowPrivilegeEscalation": False
                        }
                    }]
                }
            }
        }
    }
    response = client.post("/validate", json=admission_review_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["response"]["allowed"] is True
    assert data["response"]["uid"] == "705ab4f5-6393-11e8-b7cc-42010a800002"

def test_validate_admission_denied_on_high_severity():
    insecure_payload = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "test-uid-123",
            "object": {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "insecure-pod", "namespace": "default"},
                "spec": {
                    "containers": [{
                        "name": "root-box",
                        "image": "busybox:latest",
                        "securityContext": {"privileged": True}
                    }]
                }
            }
        }
    }
    response = client.post("/validate", json=insecure_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["response"]["allowed"] is False
    assert "PrivilegedContainer" in data["response"]["status"]["message"]