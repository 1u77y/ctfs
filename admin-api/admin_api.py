#!/usr/bin/env python3

from flask import jsonify, send_from_directory, Response, make_response, request, render_template, current_app,abort
from flask_openapi3 import OpenAPI, Info, Tag
from flask_cors import CORS
from pydantic import BaseModel, Field
from datetime import datetime
from jinja2.sandbox import SandboxedEnvironment
from urllib.parse import urlparse, quote
import os
import logging
import re

# --- Configuration ---

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(APP_ROOT, "templates")
PAGES_DIR = os.path.join(APP_ROOT, "pages")
LOG_DIR = "/var/log/ctf_admin"
STATUS_DIR = "/var/ctf_status"

MAX_TPL_BYTES = 64 * 1024  # 64 KiB
LOG_TRUNCATE = 2000
ALLOWED_IMAGE_SCHEMES = ("http", "https")
BANNED_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}

SIMPLE_ARITH_PATTERN = re.compile(r"\{\{\s*\d+\s*[\*\+\-\/]\s*\d+\s*\}\}")


FORBIDDEN_KEYWORDS = [
    "config", "request", "self", "cycler","__class__", "os", "subprocess","__subclasses__", "eval", "exec", "import", "builtins"
]

for d in [LOG_DIR, TEMPLATES_DIR, PAGES_DIR, STATUS_DIR]:
    os.makedirs(d, exist_ok=True)


logging.basicConfig(
    filename=os.path.join(LOG_DIR, "render_submissions.log"),
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

# OpenAPI info and app initialization
info = Info(
    title="Endpoints",
    version="1.0.0",
    description=(
        "This service was left in a development state — internal endpoints may be exposed. "
        "Accessible only via the training environment; do not use in production."
    )
)

backend_host = "109.205.181.210"
backend_port = 9000
nginx_host = "109.205.181.210"
nginx_port = 12000

backend_url = f"http://{backend_host}:{backend_port}/openapi/openapi.json"

# Encoder l'URL complète pour passer dans query string
encoded_backend_url = quote(backend_url, safe='')

# Construire l'URL finale via le proxy /fetch
proxy_url = f"http://{nginx_host}:{nginx_port}/fetch?url={encoded_backend_url}"

# Configure OpenAPI / Swagger UI
app = OpenAPI(
    __name__,
    info=info,
    doc_prefix="/openapi"
)

CORS(app, resources={r"/*": {"origins": "*"}})

# API Tags
admin_tag = Tag(name="Admin", description="Administrative endpoints")
template_tag = Tag(name="Templates", description="Template management and rendering")

class TemplateQuery(BaseModel):
    name: str = Field(..., description="Template filename to fetch")

class RenderRequest(BaseModel):
    template: str = Field(..., description="Template text to render")
    image_url: str | None = Field(None, description="Optional image URL")

class InsecureSandbox(SandboxedEnvironment):
    def is_safe_attribute(self, obj, attr, value):
        return True

    def is_safe_callable(self, obj):
        return True


insecure_env = InsecureSandbox()

# Helper functions
def is_safe_url(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ALLOWED_IMAGE_SCHEMES:
        return False
    if parsed.hostname is None or parsed.hostname in BANNED_HOSTNAMES:
        return False
    return True

def contains_forbidden_keyword(template_str: str) -> bool:
    lower = template_str.lower()
    return any(word in lower for word in FORBIDDEN_KEYWORDS)

def get_template_context(image_url=None):
    return {
        "username": "guest_user",
        "image_url": image_url or "https://example.org/sample.jpg",
        "server_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "notice": "Am a guest."
    }


@app.get("/")
def home():
    abort(404)
    
@app.get("/admin")
def admin():
    print(current_app.jinja_loader.searchpath)
    try:
        html = render_template("hint.html")  # ✅ correct
        print(html)
        return Response(html, status=200, mimetype="text/html")
    except Exception:
        current_app.logger.exception("Failed to render admin hint page")
        abort(404)

@app.get("/status", tags=[admin_tag], responses={
    200: {
        "description": "Service health",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "ok": {"type": "boolean"},
                        "component": {"type": "string"}
                    }
                }
            }
        }
    }
})
def status():
    """Service health"""
    return jsonify({"ok": True, "component": "admin-api"})

@app.get("/templates/list", tags=[template_tag], responses={
    200: {
        "description": "List of templates",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "templates": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    }
                }
            }
        }
    }
})
def templates_list():
    """List available template files"""
    try:
        files = [
            f for f in sorted(os.listdir(TEMPLATES_DIR))
            if not f.startswith(".")
            and f.lower().endswith((".html", ".txt"))
            and f.lower() != "hint.html"
        ]
    except FileNotFoundError:
        files = []
    return jsonify({"templates": files})


@app.get("/templates/get", tags=[template_tag], responses={
    200: {
        "description": "Template content (text/plain)",
        "content": {
            "text/plain": {
                "schema": {"type": "string"}
            }
        }
    },
    404: {"description": "Not found"}
})
def templates_get(query: TemplateQuery):
    """Return a template file (raw text)"""
    safe_name = os.path.basename(query.name)
    template_path = os.path.join(TEMPLATES_DIR, safe_name)
    if not os.path.isfile(template_path):
        return jsonify({"error": "not found"}), 404
    return send_from_directory(TEMPLATES_DIR, safe_name, mimetype="text/plain")

@app.get("/render", tags=[template_tag])
def render_page_get():
    """Return the render page UI (static HTML in pages/render_page.html)"""
    page_path = os.path.join(PAGES_DIR, "render_page.html")
    if not os.path.isfile(page_path):
        return Response("Render page not found (operator error).", status=500)
    with open(page_path, "r", encoding="utf-8") as fh:
        return fh.read()


@app.route("/render", methods=["POST"])
def render_page_post():
    # Try JSON first
    if request.is_json:
        body = request.get_json()
        raw = body.get("template")
        image_url = body.get("image_url")
    else:
        # fallback to form data
        raw = request.form.get("template")
        image_url = request.form.get("image_url")

    if not raw:
        return "No template provided", 400

    if len(raw.encode("utf-8")) > MAX_TPL_BYTES:
        return "Template too large", 413

    if image_url and not is_safe_url(image_url):
        image_url = None

    logged = (raw or "")[:LOG_TRUNCATE].replace("\n", "\\n")
    logging.info("Submission from %s: %s", request.remote_addr, logged)

    try:
        template_obj = insecure_env.from_string(raw)
        rendered = template_obj.render(**get_template_context(image_url=image_url))

        FAKE_FLAG = "SADC{render_pipeline_owned_by_you_kudos_and_tears}"
        if FAKE_FLAG in rendered:
            os.makedirs(STATUS_DIR, exist_ok=True)
            marker = os.path.join(STATUS_DIR, "fake_flag_retrieved.txt")
            with open(marker, "a") as f:
                f.write(f"{request.remote_addr} {datetime.utcnow().isoformat()}\n")
            rendered += "\n\n-- Fake flag observed by server --"

        resp_html = f"""
        <!doctype html><html><head><meta charset="utf-8"><title>Rendered Preview</title></head><body>
        <h2>Rendered output</h2>
        <div style="padding:12px;border:1px solid #ddd;background:#fff;color:black;">{rendered}</div>
        <hr>
        </body></html>
        """
        return Response(resp_html, mimetype="text/html")

    except Exception as e:
        return f"Template error: {str(e)}", 400
    
@app.post("/render/json")
def render_page_post_json(body: RenderRequest):
    raw = body.template
    if len(raw.encode("utf-8")) > MAX_TPL_BYTES:
        return jsonify({"error": "Template too large"}), 413

    if SIMPLE_ARITH_PATTERN.search(raw):
        return "Trivial arithmetic or forbidden keywords detected.", 400

    if contains_forbidden_keyword(raw):
        return "Try using creative expressions that avoid basic math or restricted words.", 400

    image_url = body.image_url
    if image_url and not is_safe_url(image_url):
        image_url = None

    logged = (raw or "")[:LOG_TRUNCATE].replace("\n", "\\n")
    logging.info("Submission (json) from %s: %s", request.remote_addr, logged)

    try:
        template = insecure_env.from_string(raw)
        rendered = template.render(**get_template_context(image_url=image_url))
        return jsonify({"rendered_html": rendered})

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# --- Main execution ---

if __name__ == "__main__":
    # Create fake flag file with ownership if possible
    os.makedirs("/home/monkey", exist_ok=True)
    fake_flag_path = "/home/monkey/flag.txt"
    if not os.path.exists(fake_flag_path):
        try:
            with open(fake_flag_path, "w") as f:
                f.write("SADC{render_pipeline_owned_by_you_kudos_and_tears}\n")
            import pwd
            try:
                uid = pwd.getpwnam('monkey').pw_uid
                gid = pwd.getpwnam('monkey').pw_gid
                os.chown(fake_flag_path, uid, gid)
            except Exception:
                pass
        except Exception:
            pass

    os.makedirs(LOG_DIR, exist_ok=True)
    app.run(host="0.0.0.0", port=9000)
