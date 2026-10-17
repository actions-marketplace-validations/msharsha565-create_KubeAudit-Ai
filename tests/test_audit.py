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