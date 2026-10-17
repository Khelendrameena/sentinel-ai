"""Template engine - Nuclei-style vulnerability checks."""
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from ..models import Finding


@dataclass
class Template:
    id: str
    name: str
    severity: str
    description: str
    match_type: str  # reflect, status, body_regex, header
    path: str = "/"
    param: str = ""
    payload: str = ""
    match_regex: str = ""
    match_status: int = 200


class TemplateEngine:
    def __init__(self, template_dir: str = "templates"):
        self.template_dir = template_dir
        self.templates: list[Template] = []

    def load(self):
        import os
        for fn in os.listdir(self.template_dir):
            if not fn.endswith((".yml", ".yaml")):
                continue
            with open(os.path.join(self.template_dir, fn)) as f:
                d = yaml.safe_load(f)
            m = d.get("match", {})
            self.templates.append(Template(
                id=d["id"], name=d.get("name", d["id"]),
                severity=d.get("severity", "medium"),
                description=d.get("description", ""),
                match_type=m.get("type", "status"),
                path=d.get("path", "/"),
                param=m.get("param", ""),
                payload=m.get("payload", ""),
                match_regex=m.get("regex", ""),
                match_status=m.get("status", 200),
            ))
        return self.templates

    async def run(self, base_url: str) -> list[Finding]:
        findings = []
        async with httpx.AsyncClient(
            trust_env=False, timeout=10, follow_redirects=True,
            headers={"User-Agent": "SentinelAI/1.0 (bug bounty)"},
        ) as client:
            for t in self.templates:
                try:
                    finding = await self._check(client, base_url, t)
                    if finding:
                        findings.append(finding)
                except Exception:
                    pass
        return findings

    async def _check(self, client, base_url: str, t: Template):
        url = urljoin(base_url, t.path)
        if t.param and t.payload:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{t.param}={t.payload}"

        if t.match_type == "reflect":
            resp = await client.get(url)
            if t.payload in resp.text:
                return Finding(t.id, t.severity, url,
                               evidence=f"Payload reflected in response ({len(resp.text)} bytes)",
                               description=t.description)
        elif t.match_type == "body_regex" and t.match_regex:
            resp = await client.get(url)
            if re.search(t.match_regex, resp.text, re.IGNORECASE):
                return Finding(t.id, t.severity, url,
                               evidence=f"Regex matched: {t.match_regex[:80]}",
                               description=t.description)
        elif t.match_type == "status":
            resp = await client.get(url)
            if resp.status_code == t.match_status and len(resp.content) > 0:
                return Finding(t.id, t.severity, url,
                               evidence=f"HTTP {resp.status_code} with {len(resp.content)} bytes",
                               description=t.description)
        return None
