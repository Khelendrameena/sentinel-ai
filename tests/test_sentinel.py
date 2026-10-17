"""Tests for Sentinel AI."""
from sentinel.models import Asset, Finding
from sentinel.scanner.templates import TemplateEngine


def test_templates_load():
    e = TemplateEngine("templates")
    t = e.load()
    assert len(t) == 6
    ids = {x.id for x in t}
    assert "xss-reflected" in ids
    assert "git-exposed" in ids


def test_finding_to_state():
    f = Finding("xss-reflected", "high", "https://t.com/search?q=x",
                evidence="reflected")
    s = f.to_state()
    assert s["template"] == "xss-reflected"
    assert "https://t.com" in s["url"]


def test_severity_order():
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    assert order["critical"] < order["high"] < order["medium"]
