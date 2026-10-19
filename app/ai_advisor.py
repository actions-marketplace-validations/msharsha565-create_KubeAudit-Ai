import json
import logging
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Literal, Optional, Union
import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("kubeaudit.ai_advisor")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:0.5b")
AI_TIMEOUT = float(os.getenv("AI_TIMEOUT", "1.5"))


class JSONPatchOp(BaseModel):
    op: Literal["add", "replace", "remove"]
    path: str
    value: Optional[Union[Dict[str, Any], List[Any], str, int, bool]] = None


class SecurityFinding(BaseModel):
    rule_id: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    description: str
    risk_factor: str
    remediation: str


class LLMAuditReport(BaseModel):
    risk_score: int = Field(default=1, ge=1, le=10)
    summary: str = "Standard audit completed."
    findings: List[SecurityFinding] = Field(default_factory=list)
    suggested_patches: List[JSONPatchOp] = Field(default_factory=list)


SYSTEM_PROMPT = """You are a Kubernetes Security Expert.
Analyze the provided manifest and detected violations.
Return STRICT JSON ONLY matching this schema:
{
  \"risk_score\": <1-10>,
  \"summary\": \"<1-2 sentence overview>\",
  \"findings\": [
    {
      \"rule_id\": \"<ID>\",
      \"severity\": \"<Critical|High|Medium|Low|Info>\",
      \"description\": \"<summary>\",
      \"risk_factor\": \"<vector>\",
      \"remediation\": \"<steps>\"
    }
  ],
  \"suggested_patches\": []
}"""


class AIAdvisor:
    def __init__(self, ollama_host: Optional[str] = None, model: str = "qwen2.5-coder:0.5b"):
        self.ollama_host = (ollama_host or os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")).rstrip("/")
        self.model = os.getenv("OLLAMA_MODEL", model)

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.ollama_host}/api/tags", headers={"User-Agent": "KubeAudit-AI"})
            with urllib.request.urlopen(req, timeout=1) as response:
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
            with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as response:
                res_data = json.loads(response.read().decode())
                return res_data.get("response", "").strip()
        except Exception as e:
            return f"Remediation guidance unavailable: {str(e)}"

    async def audit_manifest(
        self,
        manifest: Dict[str, Any],
        violations: Optional[List[Dict[str, Any]]] = None
    ) -> LLMAuditReport:
        if not self.is_available():
            return LLMAuditReport(
                risk_score=1,
                summary="AI Advisor offline; relied on baseline rules.",
                findings=[],
                suggested_patches=[]
            )

        prompt = (
            f"{SYSTEM_PROMPT}\n\n"
            f"Manifest:\n{json.dumps(manifest, indent=2)}\n\n"
            f"Violations:\n{json.dumps(violations or [], indent=2)}"
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "num_ctx": 1024,
                "num_predict": 256,
                "temperature": 0.1
            }
        }

        try:
            async with httpx.AsyncClient(timeout=AI_TIMEOUT) as client:
                response = await client.post(
                    f"{self.ollama_host}/api/generate",
                    json=payload
                )
                if response.status_code == 200:
                    raw_text = response.json().get("response", "{}")
                    parsed = json.loads(raw_text)
                    return LLMAuditReport.model_validate(parsed)
        except Exception as exc:
            pass

        return LLMAuditReport(
            risk_score=1,
            summary="AI audit timed out or unparseable; applied standard fallback.",
            findings=[],
            suggested_patches=[]
        )


ai_advisor = AIAdvisor()
