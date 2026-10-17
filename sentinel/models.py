"""Core models for Sentinel AI."""
from dataclasses import dataclass, field


@dataclass
class Asset:
    """A discovered asset (subdomain:port + service)."""
    host: str
    port: int = 443
    service: str = ""
    banner: str = ""
    is_web: bool = False


@dataclass
class Finding:
    """A vulnerability finding from template matching."""
    template_id: str
    severity: str  # critical, high, medium, low, info
    url: str
    evidence: str = ""
    description: str = ""
    # AI verification
    ai_probability: float = 0.0
    ai_verdict: str = "unverified"  # true_positive, false_positive, unverified

    def to_state(self) -> dict:
        return {
            "template": self.template_id,
            "severity": self.severity,
            "url": self.url,
            "evidence": self.evidence[:500],
            "description": self.description[:300],
        }
