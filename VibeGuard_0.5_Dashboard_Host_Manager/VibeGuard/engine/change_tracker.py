import json
from pathlib import Path

def _key(f):
    return "|".join(str(f.get(k) or "") for k in ("category","title","file","evidence"))

def annotate_changes(result: dict, reports_dir: Path) -> dict:
    reports_dir.mkdir(parents=True, exist_ok=True)
    previous = None
    for path in sorted(reports_dir.glob("vibeguard_*.json"), key=lambda p:p.stat().st_mtime, reverse=True):
        try: old=json.loads(path.read_text(encoding="utf-8"))
        except (OSError,json.JSONDecodeError): continue
        if old.get("target")==result.get("target") and old.get("scan_type")==result.get("scan_type"):
            previous=old; break
    current={_key(x):x for x in result.get("findings",[])}
    if previous is None:
        result["change_summary"]={"baseline":True,"new":0,"resolved":0,"persistent":0,
                                  "message":"Baseline scan. The next scan will identify changes."}
        return result
    old={_key(x):x for x in previous.get("findings",[])}
    new_keys=current.keys()-old.keys()
    resolved_keys=old.keys()-current.keys()
    persistent_keys=current.keys()&old.keys()
    result["change_summary"]={"baseline":False,"new":len(new_keys),"resolved":len(resolved_keys),
        "persistent":len(persistent_keys),"message":"Compared with the previous report for this exact target and scan type."}
    result["new_findings"]=[current[k] for k in sorted(new_keys)]
    result["resolved_findings"]=[old[k] for k in sorted(resolved_keys)]
    return result
