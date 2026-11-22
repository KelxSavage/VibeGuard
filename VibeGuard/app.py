from __future__ import annotations
import json, secrets, threading, webbrowser, time
from datetime import datetime
from pathlib import Path
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from scanners.secrets import scan_repository
from scanners.website import scan_website
from engine.reporter import save_report
from engine.change_tracker import annotate_changes

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR, SCOPE_FILE = BASE_DIR/"reports", BASE_DIR/"config"/"scope.json"
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_SECURE=False, MAX_CONTENT_LENGTH=32*1024)

def loopback(v): return v in ("127.0.0.1", "::1")

@app.before_request
def local_only_and_csrf():
    if not loopback(request.remote_addr) or request.host.split(":")[0] not in ("127.0.0.1","localhost"):
        abort(403)
    if request.method == "POST" and request.form.get("csrf_token") != session.get("csrf_token"):
        abort(400, "Invalid form token. Refresh and try again.")

@app.context_processor
def inject_csrf():
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return {"csrf_token":session["csrf_token"]}

def report_history():
    out=[]
    if REPORTS_DIR.exists():
        for p in sorted(REPORTS_DIR.glob("vibeguard_*.json"),key=lambda x:x.stat().st_mtime,reverse=True)[:20]:
            try:
                d=json.loads(p.read_text(encoding="utf-8"))
                out.append({"file":p.name,"type":d.get("scan_type","scan"),"target":d.get("target","unknown"),
                    "count":len(d.get("findings",[])),"when":datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")})
            except (OSError,json.JSONDecodeError): pass
    return out

@app.get("/")
def dashboard():
    history=report_history()
    return render_template("index.html",history=history,total_findings=sum(x["count"] for x in history))

@app.post("/scan/repository")
def scan_repo():
    raw=request.form.get("repo_path","").strip()
    try:
        target=Path(raw).expanduser().resolve(strict=True)
        if not target.is_dir(): raise ValueError("Path must be a folder.")
        result=scan_repository(target)
        result=annotate_changes(result,REPORTS_DIR)
        jp,_=save_report(result,REPORTS_DIR)
        flash(f"Comprehensive repository scan complete: {len(result['findings'])} finding(s).","success")
        return redirect(url_for("view_report",filename=jp.name))
    except (OSError,RuntimeError,ValueError) as exc:
        flash(f"Repository scan failed: {exc}","error"); return redirect(url_for("dashboard"))

@app.post("/scan/website")
def scan_url():
    try:
        result=scan_website(request.form.get("website_url","").strip(),SCOPE_FILE)
        result=annotate_changes(result,REPORTS_DIR)
        jp,_=save_report(result,REPORTS_DIR)
        flash(f"Website path scan complete: {len(result['findings'])} finding(s).","success")
        return redirect(url_for("view_report",filename=jp.name))
    except (ValueError,PermissionError,RuntimeError) as exc:
        flash(str(exc),"error"); return redirect(url_for("dashboard"))

@app.get("/reports/<filename>")
def view_report(filename):
    if Path(filename).name!=filename or not filename.endswith(".json"): abort(404)
    p=REPORTS_DIR/filename
    if not p.is_file(): abort(404)
    try: data=json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError: abort(500)
    return render_template("report.html",report=data,filename=filename)

@app.get("/download/<filename>")
def download_report(filename):
    from flask import send_file
    if Path(filename).name != filename or not filename.endswith(".json"): abort(404)
    md = REPORTS_DIR / (Path(filename).stem + ".md")
    if not md.is_file(): abort(404)
    return send_file(md, as_attachment=True, download_name=md.name, mimetype="text/markdown")

@app.get("/scope")
def scope():
    try:
        scope_data=json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
        origins=scope_data.get("allowed_origins",[])
        open_scope=bool(scope_data.get("allow_any_public_origin", False))
    except (OSError,json.JSONDecodeError):
        origins=[]; open_scope=False
    return render_template("scope.html",origins=origins,open_scope=open_scope)

if __name__=="__main__":
    def open_ui(): time.sleep(1); webbrowser.open("http://127.0.0.1:5055")
    threading.Thread(target=open_ui,daemon=True).start()
    print("VibeGuard 0.3 dashboard: http://127.0.0.1:5055 (loopback only)")
    app.run(host="127.0.0.1",port=5055,debug=False,use_reloader=False)
