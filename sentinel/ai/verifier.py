"""AI verifier - Jev scores each finding for true-positive probability."""
import asyncio
import os

import httpx

from ..models import Finding

QUESTION = {
    "id": "true_positive",
    "question": "Given this vulnerability scan finding with its evidence, how likely is it a TRUE POSITIVE (real vulnerability, not a false alarm)?",
    "type": "probability",
}


class AIVerifier:
    def __init__(self, api_key: str = None, threshold: float = 0.6):
        self.api_key = api_key or os.environ.get("JEV_API_KEY", "")
        self.threshold = threshold
        self.enabled = bool(self.api_key)

    async def verify(self, findings: list[Finding]) -> list[Finding]:
        if not self.enabled or not findings:
            return findings
        url = os.environ.get("JEV_API_URL", "https://api.typesafe.ai/v1/decide")
        async with httpx.AsyncClient(trust_env=False) as client:
            async def _one(f: Finding):
                try:
                    resp = await client.post(url, json={
                        "state": f.to_state(), "questions": [QUESTION],
                    }, headers={"Authorization": f"Bearer {self.api_key}"},
                        timeout=10)
                    p = float(resp.json().get("answers", {}).get("true_positive", 0))
                except Exception:
                    p = 0.0
                f.ai_probability = p
                f.ai_verdict = "true_positive" if p >= self.threshold else "false_positive"
                return f
            return await asyncio.gather(*[_one(f) for f in findings])

    def filter(self, findings: list[Finding]) -> list[Finding]:
        """Keep only AI-verified true positives (or unverified if AI off)."""
        if not self.enabled:
            return findings
        return [f for f in findings if f.ai_verdict == "true_positive"]
