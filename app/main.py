from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
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
                remediation=f"Pin container '{c_name}' image to an immutable tag or SHA256 digest (e.g., '{image.split(':')[0]}:1.0.0')."
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
                remediation="Set securityContext.readOnlyRootFilesystem: true and mount an emptyDir volume for writable temporary paths."
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