from __future__ import annotations
import datetime as dt
import json
import urllib.request
from pathlib import Path

OSV_QUERY = "https://api.osv.dev/v1/query"

class AdvisoryUnavailable(RuntimeError):
    pass

def query_osv(dep: dict, timeout: float = 15) -> dict:
    body = json.dumps({"package": {"ecosystem": dep["ecosystem"], "name": dep["name"]}, "version": dep["version"]}).encode()
    request = urllib.request.Request(OSV_QUERY, data=body, headers={"Content-Type": "application/json", "User-Agent": "dependency-risk-monitor/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except Exception as exc:
        raise AdvisoryUnavailable(str(exc)) from exc

def normalize(dep: dict, payload: dict) -> dict:
    advisories = []
    for item in payload.get("vulns", []):
        aliases = sorted(set(item.get("aliases", [])))
        refs = sorted({r["url"] for r in item.get("references", []) if r.get("url")})
        advisories.append({"id": item["id"], "aliases": aliases, "references": refs})
    advisories.sort(key=lambda x: x["id"])
    return {
        "package": dep,
        "observation": "advisories_returned" if advisories else "no_advisory_returned",
        "advisories": advisories,
    }

def semantic(report: dict) -> dict:
    return {"schema_version": report["schema_version"], "source": report["source"], "results": report["results"]}

def run(dependencies: list[dict], fetch=query_osv, now=None) -> dict:
    results = [normalize(dep, fetch(dep)) for dep in dependencies]
    stamp = (now or dt.datetime.now(dt.timezone.utc)).replace(microsecond=0).isoformat()
    return {"schema_version": 1, "source": {"name": "OSV", "url": OSV_QUERY}, "retrieved_at": stamp, "results": results}

def update_report(input_path: Path, output_path: Path, fetch=query_osv, now=None) -> bool:
    deps = json.loads(input_path.read_text(encoding="utf-8"))
    candidate = run(deps, fetch=fetch, now=now)
    if output_path.exists():
        previous = json.loads(output_path.read_text(encoding="utf-8"))
        if semantic(previous) == semantic(candidate):
            return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return True
