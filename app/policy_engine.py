import os
from typing import Any, Dict, List

POLICY_PATH = os.getenv("POLICY_PATH", "policies/kubernetes.rego")

class RegoPolicyEngine:
    def __init__(self, policy_file: str = POLICY_PATH):
        self.policy_file = policy_file
        self.rules_loaded = False
        self._load_policy()

    def _load_policy(self):
        if os.path.exists(self.policy_file):
            self.rules_loaded = True

    def evaluate(self, manifest: Dict[str, Any]) -> List[Dict[str, str]]:
        violations: List[Dict[str, str]] = []
        kind = manifest.get("kind", "")
        spec = manifest.get("spec", {})

        pod_spec = None
        if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job"]:
            pod_spec = spec.get("template", {}).get("spec", {})
        elif kind == "Pod":
            pod_spec = spec

        if pod_spec is not None:
            sec_ctx = pod_spec.get("securityContext", None)
            if not sec_ctx or not sec_ctx.get("runAsNonRoot"):
                violations.append({
                    "rule": "RunAsNonRoot",
                    "severity": "High",
                    "message": "Pod securityContext must enforce runAsNonRoot: true"
                })

            containers = pod_spec.get("containers", [])
            for c in containers:
                c_name = c.get("name", "unnamed")
                c_sec = c.get("securityContext", {})
                if c_sec.get("privileged") is True:
                    violations.append({
                        "rule": "PrivilegedContainer",
                        "severity": "Critical",
                        "message": f"Container '{c_name}' must not run in privileged mode"
                    })

                resources = c.get("resources", {})
                limits = resources.get("limits", None)
                if not limits or not limits.get("cpu") or not limits.get("memory"):
                    violations.append({
                        "rule": "MissingResourceLimits",
                        "severity": "High",
                        "message": f"Container '{c_name}' lacks CPU or Memory limits"
                    })

        return violations

policy_engine = RegoPolicyEngine()
