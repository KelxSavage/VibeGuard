import json
from datetime import datetime, timezone
from pathlib import Path

def save_report(result: dict, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = output_dir / f"vibeguard_{result['scan_type']}_{stamp}"

    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    lines = [
        "# VibeGuard Security Report",
        "",
        f"- **Target:** `{result.get('target', 'unknown')}`",
        f"- **Scan type:** `{result.get('scan_type')}`",
        f"- **Findings:** {len(result.get('findings', []))}",
        ""
    ]
    if "files_scanned" in result:
        lines.append(f"- **Files scanned:** {result['files_scanned']}")
        lines.append("")
    for index, finding in enumerate(result.get("findings", []), start=1):
        lines.extend([
            f"## {index}. [{finding['severity'].upper()}] {finding['title']}",
            f"- Category: `{finding['category']}`",
            f"- Location: `{finding.get('file') or 'website response'}`"
              + (f", line {finding['line']}" if finding.get("line") else ""),
            f"- Evidence: `{finding.get('evidence', '')}`",
            f"- Recommendation: {finding['recommendation']}",
            ""
        ])
    if not result.get("findings"):
        lines.extend(["## Result", "No configured checks reported findings.", ""])
    lines.extend(["## Notes", *[f"- {note}" for note in result.get("notes", [])], ""])
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
