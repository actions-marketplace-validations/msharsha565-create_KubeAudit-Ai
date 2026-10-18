import json
import os
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

class AIAdvisor:
    def __init__(self, ollama_host: Optional[str] = None, model: str = "qwen2.5-coder:0.5b"):
        self.ollama_host = ollama_host or os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
        self.model = os.getenv("OLLAMA_MODEL", model)

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.ollama_host}/api/tags", headers={"User-Agent": "KubeAudit-AI"})
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status == 200
        except Exception:
            return False

    def explain_violations(self, manifest_snippet: str, violations: List[str]) -> str:
        if not self.is_available() or not violations:
            return "Ensure spec.securityContext.runAsNonRoot is true and container limits are defined."

        prompt = (
            f"You are a Kubernetes Security Expert. Review this manifest and detected violations:\n"
            f"Manifest:\n{manifest_snippet}\n\n"
            f"Violations:\n" + "\n".join(f"- {v}" for v in violations) + "\n\n"
            f"Provide a concise 2-sentence actionable remediation plan explaining why these settings matter."
        )

        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_ctx": 1024,
                "num_predict": 75,
                "temperature": 0.1,
                "num_thread": 2
            }
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                f"{self.ollama_host}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=60) as response:
                res_data = json.loads(response.read().decode())
                return res_data.get("response", "").strip()
        except Exception as e:
            return f"Remediation guidance unavailable: {str(e)}"

ai_advisor = AIAdvisor()
