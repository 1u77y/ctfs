from flask import Flask, request, abort, Response, render_template, send_from_directory, redirect, jsonify
from urllib.parse import urlparse, urlunparse, quote, unquote
import socket
import ipaddress
import requests
import os
import random
import re
import html
from datetime import datetime

app = Flask(__name__, template_folder="templates", static_folder="static")

# ---------------- Configuration ----------------
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

ALLOWED_HOSTNAMES = {
    "admin-api", "public-app", "localhost", "127.0.0.1",
    "res.cloudinary.com", "picsum.photos", "109.205.181.210"
}

USER_AGENT = "CTF-Fetcher/1.0"
REQUEST_TIMEOUT = 10
FEEDBACK_LOG = "/var/log/ctf_admin/feedback.log"

# Ensure necessary directories
os.makedirs(os.path.dirname(FEEDBACK_LOG), exist_ok=True)
os.makedirs(os.path.join(app.root_path, "static", "thumbs"), exist_ok=True)

# ---------------- Helpers ----------------
def is_ip_allowed(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in ALLOWED_NETWORKS)


def resolve_hostname(hostname: str):
    """Resolve hostname to all associated IP addresses."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        return list({info[4][0] for info in infos})
    except Exception:
        return []


app.jinja_env.filters['urlencode'] = lambda u: quote(u, safe='')


# ---------------- Routes ----------------
@app.route("/")
def index():
    image_info = [
        {"url": "https://picsum.photos/id/1011/300/200", "name": "mountain"},
        {"url": "https://picsum.photos/id/1025/300/200", "name": "dog"},
        {"url": "https://picsum.photos/id/1024/300/200", "name": "vulture"},
        {"url": "https://picsum.photos/id/1020/300/200", "name": "bear in snow"},
        {"url": "https://picsum.photos/id/1031/300/200", "name": "skyscraper"},
        {"url": "https://picsum.photos/id/1003/300/200", "name": "deer"},
        {"url": "https://picsum.photos/id/1043/300/200", "name": "coffee"},
        {"url": "https://picsum.photos/id/1049/300/200", "name": "rock in sea"},
        {"url": "https://picsum.photos/id/1056/300/200", "name": "salt flat"},
        {"url": "https://picsum.photos/id/1062/300/200", "name": "dog wrapped in blanket"},
        {"url": "https://picsum.photos/id/1069/300/200", "name": "jellyfish"},
        {"url": "https://picsum.photos/id/1074/300/200", "name": "kitten"},
        {"url": "https://picsum.photos/id/1084/300/200", "name": "walrus"},
        {"url": "https://picsum.photos/id/1080/300/200", "name": "strawberries"},
        {"url": "https://picsum.photos/id/1081/300/200", "name": "modern building"},
        {"url": "https://picsum.photos/id/1082/300/200", "name": "hands playing piano"},
    ]

    random.shuffle(image_info)
    return render_template("index.html", images=image_info)


@app.post("/feedback")
def feedback():
    text = request.form.get("feedback", "").strip()
    if not text:
        return jsonify({"error": "Feedback cannot be empty"}), 400

    safe_text = text.replace("\n", "\\n").replace("\r", "\\r")
    safe_text = html.escape(safe_text)

    timestamp = datetime.utcnow().isoformat()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    log_entry = f"[{timestamp}] IP={ip} MSG={safe_text}\n"
    try:
        with open(FEEDBACK_LOG, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception:
        return jsonify({"error": "Could not write feedback"}), 500

    return redirect("")


@app.route("/status")
def status():
    return {"service": "public-app", "note": "Image gallery uses server-side fetching; internal services are reachable only from the server."}


# ------------------------------
# /fetch endpoint full
# ------------------------------
@app.route("/fetch", methods=["GET", "POST", "OPTIONS"])
@app.route("/fetch/<path:subpath>", methods=["GET", "POST", "OPTIONS"])
def fetch(subpath=None):
    # -------------------- OPTIONS --------------------
    if request.method == "OPTIONS":
        return '', 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }

    # -------------------- Determine target_url --------------------
    raw_url = request.args.get("url")
    if subpath:
        # path-based proxy: /fetch/<path>
        target_url = f"http://admin_api:9000/{subpath}"
    elif raw_url:
        # query param ?url= fallback
        target_url = unquote(raw_url.strip())
        parsed = urlparse(target_url)
        if parsed.hostname in ("localhost", "127.0.0.1", "109.205.181.210") and (parsed.port == 9000 or parsed.port is None):
            parsed = parsed._replace(netloc="admin_api:9000")
            target_url = urlunparse(parsed)
    else:
        return jsonify({"error": "Missing 'url' parameter or path"}), 400

    parsed = urlparse(target_url)

    # -------------------- Validation --------------------
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return jsonify({"error": "Invalid URL scheme or hostname"}), 400

    hostname = parsed.hostname
    resolved_ips = resolve_hostname(hostname)
    ips_allowed = all(is_ip_allowed(ip) for ip in resolved_ips) if resolved_ips else False
    if hostname not in ALLOWED_HOSTNAMES and not ips_allowed:
        return jsonify({"error": "Host not allowed"}), 403

    # -------------------- Debug --------------------
    app.logger.info(f"Fetch headers: {dict(request.headers)}")
    data_preview = request.get_data(as_text=True)[:200]
    app.logger.info(f"Fetch raw data preview: {data_preview}")

    # -------------------- Make request --------------------
    headers = {"User-Agent": USER_AGENT}
    try:
        if request.method == "POST":
            content_type_in = request.headers.get("Content-Type", "").lower()
            if "application/json" in content_type_in:
                json_data = request.get_json(silent=True) or {}
                resp = requests.post(
                    target_url, headers=headers, json=json_data,
                    timeout=REQUEST_TIMEOUT, allow_redirects=True
                )
            else:
                data = request.get_data() or None
                resp = requests.post(
                    target_url, headers=headers, data=data,
                    timeout=REQUEST_TIMEOUT, allow_redirects=True
                )
        else:
            resp = requests.get(
                target_url, headers=headers,
                timeout=REQUEST_TIMEOUT, allow_redirects=True
            )
    except requests.RequestException as e:
        app.logger.error(f"Fetch request exception: {e}")
        return jsonify({"error": "Failed to fetch URL"}), 502

    content = resp.content
    content_type = resp.headers.get("Content-Type", "application/octet-stream")

    # -------------------- HTML rewrite for Swagger --------------------
    if content_type and "text/html" in content_type.lower():
        try:
            text = content.decode("utf-8", errors="ignore")
            # base tag for relative paths
            base_tag = f'<base href="/fetch/" />'
            text = re.sub(r'(?i)<head\b[^>]*>', lambda m: m.group(0) + base_tag, text, count=1)

            # rewrite static files (swagger/flasgger_static) to /fetch/openapi/
            def rewrite_static(m):
                url_ = m.group("url").lstrip('/')
                return f'{m.group("prefix")}/fetch/{url_}'

            text = re.sub(
                r'(?P<prefix>(?:src|href)=["\'])(?P<url>(?:swagger|flasgger_static|static)/[^"\']+)',
                rewrite_static,
                text
            )

            # fix None -> null in scripts
            text = re.sub(r"<script.*?>.*?</script>", lambda m: m.group(0).replace("None", "null"), text, flags=re.DOTALL | re.IGNORECASE)

            # inject fixed Swagger JSON spec URL
            internal_url = f"http://109.205.181.210:9000/openapi/openapi.json"
            encoded_url = quote(internal_url, safe='')
            fixed_spec_url = f"/fetch?url={encoded_url}"

            override_script = f"""
            <script>
            (function() {{
                const FIXED_SPEC_URL = "{fixed_spec_url}";
                function updateSwaggerSpec() {{
                    if (window.ui && ui.specActions) {{
                        ui.specActions.updateUrl(FIXED_SPEC_URL);
                        ui.specActions.download(FIXED_SPEC_URL);
                    }}
                    const input = document.querySelector(".download-url-input");
                    if (input) input.value = FIXED_SPEC_URL;
                }}
                document.addEventListener("DOMContentLoaded", updateSwaggerSpec);
                window.addEventListener("load", updateSwaggerSpec);
                setTimeout(updateSwaggerSpec, 100);
            }})();
            </script>
            """
            text = text.replace("</body>", override_script + "</body>")
            content = text.encode("utf-8")

        except Exception as e:
            app.logger.error(f"HTML rewrite error: {e}")
            return jsonify({"error": "HTML rewriting failed"}), 500

    # -------------------- Headers --------------------
    headers_out = {
        "X-Proxy-Status": "proxied",
        "X-Proxy-Original-URL": raw_url or f"/{subpath}",
        "X-Proxy-Final-URL": resp.url,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }

    return Response(content, status=resp.status_code, headers=headers_out, content_type=content_type)


@app.route("/static/thumbs/<path:filename>")
def thumbs(filename):
    return send_from_directory(os.path.join(app.root_path, "static", "thumbs"), filename)


# ---------------- Main ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
