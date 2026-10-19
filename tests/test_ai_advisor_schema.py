import pytest
import anyio
from app.ai_advisor import AIAdvisor, LLMAuditReport, SecurityFinding, JSONPatchOp

def test_llm_audit_report_schema_validation():
    sample_report = {
        "risk_score": 8,
        "summary": "Container runs as root with privileged flag enabled.",
        "findings": [
            {
                "rule_id": "CIS-5.2.1",
                "severity": "Critical",
                "description": "Privileged container execution detected",
                "risk_factor": "Container breakout to host node",
                "remediation": "Set securityContext.privileged: false"
            }
        ],
        "suggested_patches": [
            {
                "op": "replace",
                "path": "/spec/containers/0/securityContext/privileged",
                "value": False
            }
        ]
    }

    report = LLMAuditReport.model_validate(sample_report)
    assert report.risk_score == 8
    assert len(report.findings) == 1
    assert report.findings[0].severity == "Critical"
    assert len(report.suggested_patches) == 1
    assert report.suggested_patches[0].op == "replace"

@pytest.mark.anyio
async def test_ai_advisor_offline_fallback():
    advisor = AIAdvisor(ollama_host="http://127.0.0.1:9999")
    report = await advisor.audit_manifest({"kind": "Pod", "spec": {}})
    assert isinstance(report, LLMAuditReport)
    assert report.risk_score == 1
    assert "offline" in report.summary or "fallback" in report.summary
