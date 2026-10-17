import base64
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
import yaml
from typing import List, Dict, Any, Optional

app = FastAPI(title="KubeAudit AI", version="1.0.0")

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")

class AuditRequest(BaseModel):
    manifest: str

class Issue(BaseModel):
    severity: str
    rule: str
    message: str
    remediation: Optional[str] = None

class AuditResponse(BaseModel):
    valid: bool
    issues: List[Issue]

class FixResponse(BaseModel):
    remediated_manifest: str
    applied_fixes: List[str]

def inspect_container_list(containers: List[Dict[str, Any]], container_type: str) -> List[Issue]:
    issues = []
    for container in containers:
        c_name = container.get("name", "unnamed")
        image = container.get("image", "")

        if ":" not in image or image.endswith(":latest"):
            issues.append(Issue(
                severity="Medium",
                rule="AvoidLatestTag",
                message=f"{container_type} '{c_name}' uses the ':latest' image tag or omitted tag.",
                remediation=f"Pin container '{c_name}' image to an immutable tag or SHA256 digest."
            ))

        resources = container.get("resources", {})
        limits = resources.get("limits", {})
        requests = resources.get("requests", {})

        if not limits.get("cpu") or not limits.get("memory"):
            issues.append(Issue(
                severity="High",
                rule="MissingResourceLimits",
                message=f"{container_type} '{c_name}' lacks explicit CPU or Memory limits.",
                remediation="Configure resources.limits: { cpu: '500m', memory: '512Mi' }."
            ))

        if not requests.get("cpu") or not requests.get("memory"):
            issues.append(Issue(
                severity="Low",
                rule="MissingResourceRequests",
                message=f"{container_type} '{c_name}' lacks explicit CPU or Memory requests.",
                remediation="Configure resources.requests: { cpu: '100m', memory: '128Mi' }."
            ))

        c_sec_ctx = container.get("securityContext", {})
        if c_sec_ctx.get("privileged", False):
            issues.append(Issue(
                severity="Critical",
                rule="PrivilegedContainer",
                message=f"{container_type} '{c_name}' runs in privileged mode.",
                remediation="Set securityContext.privileged: false and drop unnecessary capabilities."
            ))

        if not c_sec_ctx.get("readOnlyRootFilesystem", False):
            issues.append(Issue(
                severity="Medium",
                rule="ReadOnlyRootFilesystem",
                message=f"{container_type} '{c_name}' does not configure 'readOnlyRootFilesystem: true'.",
                remediation="Set securityContext.readOnlyRootFilesystem: true."
            ))

        if c_sec_ctx.get("allowPrivilegeEscalation", True):
            issues.append(Issue(
                severity="High",
                rule="AllowPrivilegeEscalation",
                message=f"{container_type} '{c_name}' allows privilege escalation.",
                remediation="Set securityContext.allowPrivilegeEscalation: false."
            ))
    return issues

def analyze_manifest(doc: Dict[str, Any]) -> List[Issue]:
    issues = []
    kind = doc.get("kind", "")
    metadata = doc.get("metadata", {})
    spec = doc.get("spec", {})

    if not metadata.get("namespace") and kind not in ["Namespace", "ClusterRole", "ClusterRoleBinding"]:
        issues.append(Issue(
            severity="Medium",
            rule="RequireNamespace",
            message=f"{kind} '{metadata.get('name', 'unnamed')}' does not specify an explicit namespace.",
            remediation=f"Add metadata.namespace to '{metadata.get('name', 'unnamed')}'."
        ))

    pod_spec = None
    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
        pod_spec = spec.get("template", {}).get("spec", {})
    elif kind == "Pod":
        pod_spec = spec

    if pod_spec:
        sec_ctx = pod_spec.get("securityContext", {})
        if not sec_ctx.get("runAsNonRoot"):
            issues.append(Issue(
                severity="High",
                rule="RunAsNonRoot",
                message="Pod specification does not enforce 'runAsNonRoot: true'.",
                remediation="Configure spec.securityContext.runAsNonRoot: true."
            ))

        issues.extend(inspect_container_list(pod_spec.get("containers", []), "Container"))
        issues.extend(inspect_container_list(pod_spec.get("initContainers", []), "InitContainer"))
        issues.extend(inspect_container_list(pod_spec.get("ephemeralContainers", []), "EphemeralContainer"))

    return issues

def patch_container(container: Dict[str, Any], fixes: List[str]):
    c_name = container.get("name", "unnamed")
    
    image = container.get("image", "")
    if ":" not in image or image.endswith(":latest"):
        base_image = image.split(":")[0] if ":" in image else image
        fallback_image = f"{base_image}:alpine" if base_image == "nginx" else f"{base_image}:1.0.0"
        container["image"] = fallback_image
        fixes.append(f"Pinned image for container '{c_name}' from '{image}' to '{fallback_image}'")
    sec_ctx = container.setdefault("securityContext", {})
    if sec_ctx.get("privileged", False):
        sec_ctx["privileged"] = False
        fixes.append(f"Disabled privileged mode on container '{c_name}'")
    if not sec_ctx.get("readOnlyRootFilesystem", False):
        sec_ctx["readOnlyRootFilesystem"] = True
        fixes.append(f"Enforced readOnlyRootFilesystem on container '{c_name}'")
    if sec_ctx.get("allowPrivilegeEscalation", True):
        sec_ctx["allowPrivilegeEscalation"] = False
        fixes.append(f"Disabled allowPrivilegeEscalation on container '{c_name}'")

    resources = container.setdefault("resources", {})
    limits = resources.setdefault("limits", {})
    requests = resources.setdefault("requests", {})

    if not limits.get("cpu"):
        limits["cpu"] = "500m"
        fixes.append(f"Added default CPU limit (500m) on container '{c_name}'")
    if not limits.get("memory"):
        limits["memory"] = "512Mi"
        fixes.append(f"Added default Memory limit (512Mi) on container '{c_name}'")
    if not requests.get("cpu"):
        requests["cpu"] = "100m"
        fixes.append(f"Added default CPU request (100m) on container '{c_name}'")
    if not requests.get("memory"):
        requests["memory"] = "128Mi"
        fixes.append(f"Added default Memory request (128Mi) on container '{c_name}'")

def remediate_document(doc: Dict[str, Any], fixes: List[str]):
    kind = doc.get("kind", "")
    metadata = doc.setdefault("metadata", {})
    spec = doc.setdefault("spec", {})

    if not metadata.get("namespace") and kind not in ["Namespace", "ClusterRole", "ClusterRoleBinding"]:
        metadata["namespace"] = "default"
        fixes.append(f"Assigned namespace 'default' to {kind} '{metadata.get('name', 'unnamed')}'")

    pod_spec = None
    if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
        template = spec.setdefault("template", {})
        pod_spec = template.setdefault("spec", {})
    elif kind == "Pod":
        pod_spec = spec

    if pod_spec:
        sec_ctx = pod_spec.setdefault("securityContext", {})
        if not sec_ctx.get("runAsNonRoot"):
            sec_ctx["runAsNonRoot"] = True
            fixes.append("Enforced spec.securityContext.runAsNonRoot: true")

        for c in pod_spec.get("containers", []):
            patch_container(c, fixes)
        for c in pod_spec.get("initContainers", []):
            patch_container(c, fixes)
        for c in pod_spec.get("ephemeralContainers", []):
            patch_container(c, fixes)

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/audit", response_model=AuditResponse)
def audit_manifest(payload: AuditRequest):
    try:
        documents = list(yaml.safe_load_all(payload.manifest))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML payload: {str(e)}")

    valid_docs = [doc for doc in documents if isinstance(doc, dict)]
    if not valid_docs:
        raise HTTPException(status_code=400, detail="Manifest does not contain valid YAML object definitions.")

    all_issues = []
    for doc in valid_docs:
        all_issues.extend(analyze_manifest(doc))

    return AuditResponse(valid=(len(all_issues) == 0), issues=all_issues)

@app.post("/fix", response_model=FixResponse)
def fix_manifest(payload: AuditRequest):
    try:
        documents = list(yaml.safe_load_all(payload.manifest))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML payload: {str(e)}")

    valid_docs = [doc for doc in documents if isinstance(doc, dict)]
    if not valid_docs:
        raise HTTPException(status_code=400, detail="Manifest does not contain valid YAML object definitions.")

    applied_fixes = []
    for doc in valid_docs:
        remediate_document(doc, applied_fixes)

    remediated_yaml = yaml.dump_all(valid_docs, sort_keys=False)
    return FixResponse(remediated_manifest=remediated_yaml, applied_fixes=applied_fixes)

@app.post("/validate")
async def validate_admission(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON in admission request")

    req = body.get("request", {})
    uid = req.get("uid", "")
    object_spec = req.get("object", {})

    if not object_spec:
        return JSONResponse(content={
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {"uid": uid, "allowed": True}
        })

    issues = analyze_manifest(object_spec)
    critical_or_high = [i for i in issues if i.severity in ["Critical", "High"]]

    if critical_or_high:
        rejection_reasons = "; ".join([f"{i.rule}: {i.message}" for i in critical_or_high])
        return JSONResponse(content={
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": False,
                "status": {
                    "code": 403,
                    "message": f"KubeAudit AI policy violations: {rejection_reasons}"
                }
            }
        })

    return JSONResponse(content={
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {"uid": uid, "allowed": True}
    })