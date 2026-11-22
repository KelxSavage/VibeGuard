import argparse
import json
from pathlib import Path
from scanners.secrets import scan_repository
from scanners.website import scan_website
from engine.reporter import save_report

def main():
    parser = argparse.ArgumentParser(
        description="VibeGuard: local-first authorized security scanner"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    repo = sub.add_parser("scan-repo", help="Scan a local source directory for secret-like patterns")
    repo.add_argument("path", help="Directory you own or are authorized to scan")

    url = sub.add_parser("scan-url", help="Passively inspect one allowlisted website origin")
    url.add_argument("url", help="Exact origin, e.g. http://127.0.0.1:8765")

    args = parser.parse_args()

    if args.command == "scan-repo":
        target = Path(args.path).expanduser().resolve()
        if not target.exists() or not target.is_dir():
            parser.error(f"Directory does not exist: {target}")
        result = scan_repository(target)
    else:
        result = scan_website(args.url, Path("config/scope.json"))

    json_path, md_path = save_report(result, Path("reports"))
    print(json.dumps({
        "status": "complete",
        "findings": len(result["findings"]),
        "json_report": str(json_path),
        "markdown_report": str(md_path)
    }, indent=2))

if __name__ == "__main__":
    main()
