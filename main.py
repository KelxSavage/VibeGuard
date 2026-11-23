import argparse
import json
from pathlib import Path
from scanners.secrets import scan_repository
from scanners.website import scan_website
from engine.reporter import save_report
from engine.change_tracker import annotate_changes

BASE_DIR = Path(__file__).resolve().parent

def main():
    parser = argparse.ArgumentParser(
        description="VibeGuard: local-first authorized security scanner"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    repo = sub.add_parser("scan-repo", help="Scan a local source directory for secret-like patterns")
    repo.add_argument("path", help="Directory you own or are authorized to scan")
    repo.add_argument("--profile", choices=("production", "comprehensive", "git_history"), default="comprehensive",
                      help="production: deployable app files; comprehensive: broad current tree; git_history: commit history only")

    url = sub.add_parser("scan-url", help="Passively inspect one authorized website page or route")
    url.add_argument("url", help="Page URL, e.g. https://example.com/guestbook")

    args = parser.parse_args()

    if args.command == "scan-repo":
        target = Path(args.path).expanduser().resolve()
        if not target.exists() or not target.is_dir():
            parser.error(f"Directory does not exist: {target}")
        result = scan_repository(target, profile=args.profile, suppression_file=BASE_DIR / "config" / "suppressions.json")
    else:
        result = scan_website(args.url, BASE_DIR / "config" / "scope.json")

    reports_dir = BASE_DIR / "reports"
    result = annotate_changes(result, reports_dir)
    json_path, md_path = save_report(result, reports_dir)
    print(json.dumps({
        "status": "complete",
        "findings": len(result["findings"]),
        "json_report": str(json_path),
        "markdown_report": str(md_path)
    }, indent=2))

if __name__ == "__main__":
    main()
