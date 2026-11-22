import json
from datetime import datetime, timezone
from pathlib import Path

def save_report(result: dict, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    base = output_dir / f"vibeguard_{result['scan_type']}_{stamp}"
    json_path, md_path = base.with_suffix(".json"), base.with_suffix(".md")
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    lines = ["# VibeGuard Security Report", "", f"- **Target:** `{result.get('target','unknown')}`",
             f"- **Scan type:** `{result.get('scan_type')}`", f"- **Findings:** {len(result.get('findings',[]))}", ""]
    for i, f in enumerate(result.get("findings",[]),1):
        lines += [f"## {i}. [{f['severity'].upper()}] {f['title']}", f"- Category: `{f['category']}`",
                  f"- Location: `{f.get('file') or 'website response'}`" + (f", line {f['line']}" if f.get("line") else ""),
                  f"- Evidence: `{f.get('evidence','')}`", f"- Recommendation: {f['recommendation']}", ""]
    if not result.get("findings"): lines += ["## Result", "No configured checks reported findings.", ""]
    lines += ["## Notes", *[f"- {n}" for n in result.get("notes",[])], ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
