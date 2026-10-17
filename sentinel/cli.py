"""Sentinel AI CLI."""
import argparse
import asyncio
import json
import sys
import time

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


async def scan_target(target: str, ai_verify: bool, ports: bool) -> list:
    from urllib.parse import urlparse
    from sentinel.recon.portscan import PortScanner
    from sentinel.scanner.templates import TemplateEngine
    from sentinel.ai.verifier import AIVerifier

    domain = urlparse(target).netloc or target
    base = target if target.startswith("http") else f"https://{target}"
    t0 = time.time()
    all_findings = []

    # Phase 1: Port scan (optional)
    if ports:
        print("[1/3] Port scanning...", file=sys.stderr)
        ps = PortScanner()
        assets = await ps.scan(domain)
        for a in assets:
            print(f"    {a.host}:{a.port} {a.service}", file=sys.stderr)
    else:
        print("[1/3] Skipping port scan", file=sys.stderr)

    # Phase 2: Template matching
    print("[2/3] Running vulnerability templates...", file=sys.stderr)
    engine = TemplateEngine()
    n = len(engine.load())
    print(f"    {n} templates loaded", file=sys.stderr)
    findings = await engine.run(base)
    print(f"    [{time.time()-t0:.0f}s] {len(findings)} raw findings",
          file=sys.stderr)

    # Phase 3: AI verification
    if ai_verify:
        print("[3/3] AI verifying findings...", file=sys.stderr)
        verifier = AIVerifier()
        if verifier.enabled:
            findings = await verifier.verify(findings)
            tp = [f for f in findings if f.ai_verdict == "true_positive"]
            print(f"    {len(tp)}/{len(findings)} verified true positives",
                  file=sys.stderr)
            findings = tp
        else:
            print("    (JEV_API_KEY not set, skipping)", file=sys.stderr)
    else:
        print("[3/3] Skipping AI verification", file=sys.stderr)

    # Sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f.severity, 5), -f.ai_probability))
    return findings


def main():
    p = argparse.ArgumentParser(prog="sentinel")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("target")
    s.add_argument("--ai-verify", action="store_true")
    s.add_argument("--ports", action="store_true")
    s.add_argument("-o", "--output")
    args = p.parse_args()

    findings = asyncio.run(scan_target(args.target, args.ai_verify, args.ports))
    out = [{
        "template": f.template_id, "severity": f.severity,
        "url": f.url, "evidence": f.evidence,
        "ai_probability": round(f.ai_probability, 3),
        "ai_verdict": f.ai_verdict,
    } for f in findings]

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"[+] Report: {args.output}", file=sys.stderr)
    else:
        print(json.dumps(out, indent=2))

    print("\n=== FINDINGS ===", file=sys.stderr)
    for f in findings[:20]:
        ai = f" [AI:{f.ai_probability:.0%}]" if f.ai_probability else ""
        print(f"  [{f.severity.upper():8s}] {f.template_id}{ai}\n    {f.url}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
