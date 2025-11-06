#!/usr/bin/env python3

from flask import jsonify, send_from_directory, Response, make_response, request
from flask_openapi3 import OpenAPI, Info, Tag
from flask_cors import CORS
from pydantic import BaseModel, Field
from datetime import datetime
from jinja2.sandbox import SandboxedEnvironment
from urllib.parse import urlparse
import os
import logging

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

# Ensure necessary directories exist
for d in [LOG_DIR, TEMPLATES_DIR, PAGES_DIR, STATUS_DIR]:
    os.makedirs(d, exist_ok=True)

# Setup logging
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

app = OpenAPI(
    __name__,
    info=info,
    servers=[{"url": "http://localhost:9000"}],
    doc_prefix="/openapi"
)

# Enable CORS for all routes (adjust origins for production)
CORS(app, resources={r"/*": {"origins": "*"}})

# API Tags
admin_tag = Tag(name="Admin", description="Administrative endpoints")
template_tag = Tag(name="Templates", description="Template management and rendering")

# Insecure sandbox environment (intentionally vulnerable SSTI CTF)
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

def get_template_context(image_url=None):
    return {
        "username": "guest_user",
        "image_url": image_url or "https://example.org/sample.jpg",
        "server_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "notice": "This is an intentionally vulnerable sandbox for CTF use."
    }

# --- Endpoints ---

@app.get("/admin", tags=[admin_tag], responses={
    200: {
        "description": "Admin service metadata",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "service": {"type": "string"},
                        "version": {"type": "string"},
                        "notes": {"type": "string"}
                    }
                }
            }
        }
    }
})
def admin():
    """Admin metadata"""
    return jsonify({
        "service": "admin",
        "version": "1.0.0",
        "notes": "Those who look beyond the surface might find hidden paths. Try Harder"
    })

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
            if not f.startswith(".") and f.lower().endswith((".html", ".txt"))
        ]
    except FileNotFoundError:
        files = []
    return jsonify({"templates": files})

class TemplateQuery(BaseModel):
    name: str = Field(..., description="Template filename to fetch")

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

@app.get("/render", tags=[template_tag], responses={
    200: {
        "description": "Render page HTML",
        "content": {
            "text/html": {
                "schema": {"type": "string"}
            }
        }
    },
    500: {"description": "Operator error"}
})
def render_page_get():
    """Return the render page UI (static HTML in pages/render_page.html)"""
    page_path = os.path.join(PAGES_DIR, "render_page.html")
    if not os.path.isfile(page_path):
        return Response("Render page not found (operator error).", status=500)
    with open(page_path, "r", encoding="utf-8") as fh:
        return fh.read()

@app.post("/render", tags=[template_tag], responses={
    200: {
        "description": "Rendered HTML preview",
        "content": {
            "text/html": {"schema": {"type": "string"}},
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {"rendered_html": {"type": "string"}}
                }
            }
        }
    },
    400: {"description": "Template error"},
    413: {"description": "Template too large"}
})
def render_page_post():
    """Render submitted template text"""
    raw = request.form.get("template") or request.get_data(as_text=True) or ""
    if len(raw.encode("utf-8")) > MAX_TPL_BYTES:
        return "Template too large", 413

    image_url = request.form.get("image_url")
    if image_url and not is_safe_url(image_url):
        image_url = None

    logged = (raw or "")[:LOG_TRUNCATE].replace("\n", "\\n")
    logging.info("Submission from %s: %s", request.remote_addr, logged)

    try:
        template = insecure_env.from_string(raw)
        rendered = template.render(**get_template_context(image_url=image_url))

        FAKE_FLAG = "FLAG{non_root_rce_obtained}"
        if FAKE_FLAG in rendered:
            os.makedirs(STATUS_DIR, exist_ok=True)
            marker = os.path.join(STATUS_DIR, "fake_flag_retrieved.txt")
            with open(marker, "a") as f:
                f.write(f"{request.remote_addr} {datetime.utcnow().isoformat()}\n")
            rendered += "\n\n-- Fake flag observed by server --"

        resp_html = f"""
        <!doctype html><html><head><meta charset="utf-8"><title>Rendered Preview</title></head><body>
        <h2>Rendered output</h2>
        <div style="padding:12px;border:1px solid #ddd;background:#fff">{rendered}</div>
        <hr>
        <p><a href="/render">Back to template preview</a></p>
        </body></html>
        """
        return Response(resp_html, mimetype="text/html")

    except Exception as e:
        return f"Template error: {str(e)}", 400

@app.post("/render/json", tags=[template_tag], responses={
    200: {
        "description": "Rendered HTML wrapped in JSON (for Swagger UI)",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {"rendered_html": {"type": "string"}}
                }
            }
        }
    },
    400: {"description": "Template error"},
    413: {"description": "Template too large"}
})
def render_page_post_json():
    """Render submitted template and return JSON (Swagger-friendly)"""
    raw = request.form.get("template") or request.get_data(as_text=True) or ""
    if len(raw.encode("utf-8")) > MAX_TPL_BYTES:
        return jsonify({"error": "Template too large"}), 413

    image_url = request.form.get("image_url")
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

@app.get("/openapi/openapi.json")
def openapi_json():
    """Explicit route to serve raw OpenAPI JSON spec"""
    resp = make_response(app.openapi)
    resp.headers["Content-Type"] = "application/json"
    return resp

# --- Main execution ---

if __name__ == "__main__":
    # Create fake flag file with ownership if possible
    os.makedirs("/home/monkey", exist_ok=True)
    fake_flag_path = "/home/monkey/flag.txt"
    if not os.path.exists(fake_flag_path):
        try:
            with open(fake_flag_path, "w") as f:
                f.write("FLAG{non_root_rce_obtained}\n")
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
