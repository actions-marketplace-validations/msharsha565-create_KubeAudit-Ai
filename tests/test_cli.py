import pytest
from app.cli import audit_file, fix_file
import tempfile
import yaml
from pathlib import Path

def test_cli_audit_passes_on_compliant_manifest():
    compliant_doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "secure-app", "namespace": "default"},
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
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        yaml.dump(compliant_doc, f)
        temp_path = f.name

    try:
        audit_file(temp_path, exit_on_fail=True)
    finally:
        Path(temp_path).unlink(missing_ok=True)

def test_cli_fix_remediates_manifest():
    insecure_doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "insecure-app"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "web", "image": "nginx:latest"}
                    ]
                }
            }
        }
    }
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        yaml.dump(insecure_doc, f)
        temp_path = f.name

    try:
        fix_file(temp_path)
        with open(temp_path, "r") as f:
            fixed = yaml.safe_load(f)
        pod_spec = fixed["spec"]["template"]["spec"]
        assert pod_spec["securityContext"]["runAsNonRoot"] is True
        assert pod_spec["containers"][0]["resources"]["limits"]["cpu"] == "500m"
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_cli_advise_success(monkeypatch, tmp_path):
    import io
    import json
    import urllib.request
    from app.cli import main

    test_yaml = tmp_path / "insecure.yaml"
    test_yaml.write_text("apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: nginx\n")

    fake_response_data = {
        "available": False,
        "violations": ["RunAsNonRoot: Pod specification does not enforce runAsNonRoot."],
        "advice": "Set spec.securityContext.runAsNonRoot to true."
    }

    class FakeResponse:
        def read(self):
            return json.dumps(fake_response_data).encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=60: FakeResponse())
    monkeypatch.setattr("sys.argv", ["kubeaudit", "advise", str(test_yaml)])

    ret = main()
    assert ret == 0
