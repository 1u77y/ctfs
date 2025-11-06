#!/usr/bin/env python3
from flask import request, jsonify, send_from_directory, Response
from datetime import datetime
from flask_cors import CORS
import os
import logging
from urllib.parse import urlparse
from jinja2.sandbox import SandboxedEnvironment
from flask_openapi3 import OpenAPI, Info, Tag


# --- Configuration ---
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(APP_ROOT, "templates")    
PAGES_DIR = os.path.join(APP_ROOT, "pages")            
LOG_DIR = "/var/log/ctf_admin"
STATUS_DIR = "/var/ctf_status"

# Limits / safety
MAX_TPL_BYTES = 64 * 1024  # 64 KiB
LOG_TRUNCATE = 2000
ALLOWED_IMAGE_SCHEMES = ("http", "https")

BANNED_HOSTNAMES = ("localhost", "127.0.0.1", "::1")

# ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(PAGES_DIR, exist_ok=True)
os.makedirs(STATUS_DIR, exist_ok=True)

# logging setup
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "render_submissions.log"),
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

info = Info(
    title="Endpoints",
    version="1.0.0",
    description=(
        "This service was left in a "
        "development state — internal endpoints may be exposed. Accessible only via the "
        "training environment; do not use in production."
    )
)

# serve docs under /openapi (UI) and /openapi/openapi.json (raw spec)
app = OpenAPI(__name__, info=info, servers=[{"url": "http://localhost:9000"}], doc_prefix="/openapi")

# Enable CORS for all routes (adjust origins for production)
CORS(app, resources={r"/*": {"origins": "*"}})

# Tags for UI grouping
admin_tag = Tag(name="Admin", description="Administrative endpoints")
template_tag = Tag(name="Templates", description="Template management and rendering")


# === Insecure sandbox (intentionally vulnerable to SSTI for CTF) ===
class InsecureSandbox(SandboxedEnvironment):
    """
    Insecure sandbox: overrides safety checks to allow attribute access and
    calling of attributes — this makes SSTI exploitation feasible.
    """
    def is_safe_attribute(self, obj, attr, value):
        # Returning True here disables the sandbox attribute checks
        # and lets templates access attributes like __class__, func_globals, etc.
        return True

    def is_safe_callable(self, obj):
        # Allow calling of any callable from templates
        return True

# instantiate the insecure sandbox
insecure_env = InsecureSandbox()


# === Helpers ===
def is_safe_url(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ALLOWED_IMAGE_SCHEMES:
        return False
    if parsed.hostname is None:
        return False
    if parsed.hostname in BANNED_HOSTNAMES:
        return False
    return True


def get_template_context(image_url=None):
    return {
        "username": "guest_user",
        "image_url": image_url or "https://example.org/sample.jpg",
        "server_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "notice": "This is an intentionally vulnerable sandbox for CTF use."
    }


# === Endpoints ===
@app.get("/admin", tags=[admin_tag])
def admin():
    """Admin metadata"""
    return jsonify({
        "service": "admin",
        "version": "1.0.0",
        "notes": "Those who look beyond the surface might find hidden paths. Try Harder"
    })


@app.get("/status", tags=[admin_tag])
def status():
    """Service health"""
    return jsonify({"ok": True, "component": "admin-api"})


@app.get("/templates/list", tags=[template_tag])
def templates_list():
    """List available template files"""
    files = []
    try:
        for p in sorted(os.listdir(TEMPLATES_DIR)):
            if p.startswith("."):
                continue
            if p.lower().endswith((".html", ".txt")):
                files.append(p)
    except FileNotFoundError:
        pass
    return jsonify({"templates": files})


@app.get("/templates/get", tags=[template_tag])
def templates_get():
    """Return a template file (raw text)
    ---
    parameters:
      - name: name
        in: query
        required: true
        schema:
          type: string
        description: Template filename to fetch
    """
    name = request.args.get("name", "")
    safe_name = os.path.basename(name)
    template_path = os.path.join(TEMPLATES_DIR, safe_name)
    if not os.path.isfile(template_path):
        return jsonify({"error": "not found"}), 404
    # use send_from_directory to preserve correct headers
    return send_from_directory(TEMPLATES_DIR, safe_name, mimetype="text/plain")


# Render page UI (GET) and render submission (POST)
@app.get("/render", tags=[template_tag])
def render_page_get():
    """Return the render page UI (static HTML in pages/render_page.html)"""
    page_path = os.path.join(PAGES_DIR, "render_page.html")
    if not os.path.isfile(page_path):
        return Response("Render page not found (operator error).", status=500)
    with open(page_path, "r", encoding="utf-8") as fh:
        return fh.read()


@app.post("/render", tags=[template_tag])
def render_page_post():
    """Render submitted template text
    Request body may be form-encoded or raw text/plain
    """
    raw = request.form.get("template") or request.get_data(as_text=True) or ""
    if len(raw.encode("utf-8")) > MAX_TPL_BYTES:
        return ("Template too large", 413)
    template_src = raw

    image_url = request.form.get("image_url") or None
    if image_url and not is_safe_url(image_url):
        # remove unsafe image URL to avoid SSRF / local host fetches
        image_url = None

    # log submission (truncate to avoid huge log lines)
    logged = (template_src or "")[:LOG_TRUNCATE].replace("\n", "\\n")
    logging.info("Submission from %s: %s", request.remote_addr, logged)

    ctx = get_template_context(image_url=image_url)
    try:
        # Use the intentionally insecure sandbox (makes SSTI exploitation possible)
        template = insecure_env.from_string(template_src)
        rendered = template.render(**ctx)

        # detect fake flag and mark solved
        FAKE_FLAG = "FLAG{non_root_rce_obtained}"
        if FAKE_FLAG in rendered:
            os.makedirs(STATUS_DIR, exist_ok=True)
            marker = os.path.join(STATUS_DIR, "fake_flag_retrieved.txt")
            with open(marker, "a") as f:
                f.write(f"{request.remote_addr} {datetime.utcnow().isoformat()}\n")
            rendered = rendered + "\n\n-- Fake flag observed by server (stage 3) --"

        resp_html = f"""
        <!doctype html><html><head><meta charset="utf-8"><title>Rendered Preview</title></head>
        <body>
          <h2>Rendered output</h2>
          <div style="padding:12px;border:1px solid #ddd;background:#fff">{rendered}</div>
          <hr>
          <p><a href="/render">Back to template preview</a></p>
        </body></html>
        """
        resp = Response(resp_html, mimetype="text/html")
        # restrictive CSP - adjust img-src if you want to allow more external hosts
        resp.headers['Content-Security-Policy'] = (
            "default-src 'none'; "
            "img-src 'self' https:; "
            "style-src 'self' 'unsafe-inline';"
        )
        return resp

    except Exception as e:
        return (f"Template error: {str(e)}", 400)


# === Run ===
if __name__ == "__main__":
    # create fake flag in non-root home (only if not present)
    os.makedirs("/home/monkey", exist_ok=True)
    fake_flag_path = "/home/monkey/flag.txt"
    if not os.path.exists(fake_flag_path):
        try:
            with open(fake_flag_path, "w") as f:
                f.write("FLAG{non_root_rce_obtained}\n")
            # best-effort chown if "monkey" user exists
            import pwd
            try:
                uid = pwd.getpwnam('monkey').pw_uid
                gid = pwd.getpwnam('monkey').pw_gid
                os.chown(fake_flag_path, uid, gid)
            except Exception:
                pass
        except Exception:
            pass

    # ensure log dir exists
    os.makedirs(LOG_DIR, exist_ok=True)

    # Start app
    app.run(host="0.0.0.0", port=9000)
