import pytest
from unittest.mock import patch, MagicMock
from app.ai_advisor import AIAdvisor

def test_ai_advisor_fallback_when_unavailable():
    advisor = AIAdvisor(ollama_host="http://127.0.0.1:99999")
    with patch.object(advisor, "is_available", return_value=False):
        advice = advisor.explain_violations("apiVersion: v1", ["RunAsNonRoot"])
        assert "Ensure spec.securityContext.runAsNonRoot is true" in advice

def test_ai_advisor_generation_mock():
    advisor = AIAdvisor()
    with patch.object(advisor, "is_available", return_value=True), \
         patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"response": "Set runAsNonRoot to true."}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        advice = advisor.explain_violations("apiVersion: v1", ["RunAsNonRoot"])
        assert "Set runAsNonRoot to true." in advice
