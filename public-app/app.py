from flask import Flask, request, abort, Response, render_template, send_from_directory
from urllib.parse import urlparse, urlunparse, quote, unquote
import socket
import ipaddress
import requests
import os
import random
import re

app = Flask(__name__, template_folder="templates", static_folder="static")

# ---------------- Configuration ----------------
ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

ALLOWED_HOSTNAMES = {
    "admin-api", "suid-sim", "public-app", "localhost", "127.0.0.1",
    "res.cloudinary.com",
}

USER_AGENT = "CTF-Fetcher/1.0"
REQUEST_TIMEOUT = 10

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

# ---------------- Image Gallery ----------------
@app.route("/")
def index():
    images = [
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/sample.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/kitten.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/dog.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/bird.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/landscape.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/cat.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/flowers.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/beach.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/coffee.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/car.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/mountain.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/tree.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/food.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/sunset.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/waterfall.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/city.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/forest.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/bridge.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/boat.jpg",
        "https://res.cloudinary.com/demo/image/upload/w_300,h_200,c_fill/house.jpg",
    ]

    random.shuffle(images)
    image_info = [{"url": url, "name": os.path.basename(urlparse(url).path).split('.')[0]} for url in images]
    return render_template("index.html", images=image_info)

@app.route("/status")
def status():
    return {"service": "public-app", "note": "Image gallery uses server-side fetching; internal services are reachable only from the server."}

# ---------------- Fetch Proxy ----------------
@app.route("/fetch", methods=["GET", "OPTIONS"])
def fetch():
    if request.method == "OPTIONS":
        return '', 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }

    raw_url = request.args.get("url")
    if not raw_url:
        abort(400, "Missing 'url' parameter")

    target_url = unquote(raw_url.strip())


    if target_url == "http://localhost/openapi.json":
        target_url = "http://localhost:9000/openapi/openapi.json"

    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        abort(400, "Unsupported URL scheme or missing hostname")

    hostname = parsed.hostname
    port = parsed.port or (80 if parsed.scheme == "http" else 443)

    if hostname in ("localhost", "127.0.0.1") and port == 9000:
        parsed = parsed._replace(netloc="admin_api:9000")
        target_url = urlunparse(parsed)
        hostname = "admin_api"

    # SSRF filter
    resolved_ips = resolve_hostname(hostname)
    ips_allowed = all(is_ip_allowed(ip) for ip in resolved_ips) if resolved_ips else False
    if hostname not in ALLOWED_HOSTNAMES and not ips_allowed:
        return "Blocked by SSRF filter: external hosts not allowed", 403

    # Fetch target
    try:
        headers = {"User-Agent": USER_AGENT}
        resp = requests.get(target_url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        return f"Error fetching target: {e}", 502

    content = resp.content
    content_type = resp.headers.get("Content-Type", "application/octet-stream")


    if content_type and "text/html" in content_type.lower():
        try:
            text = content.decode("utf-8", errors="ignore")
            # Inject <base> tag
            base_tag = f'<base href="/fetch?url={quote(target_url, safe="")}" />'
            text = re.sub(r'(?i)<head\b[^>]*>', lambda m: m.group(0) + base_tag, text, count=1)

            # Rewrite relative static assets
            def rewrite_static(m):
                url = m.group("url").lstrip('/')
                full_url = f"http://localhost:9000/openapi/{url}" if url.startswith("swagger") else f"{parsed.scheme}://{parsed.netloc}/{url}"
                return f'{m.group("prefix")}/fetch?url=' + quote(full_url, safe='')

            text = re.sub(
                r'(?P<prefix>(?:src|href)=["\'])(?P<url>(?:swagger|flasgger_static|static)/[^"\']+)',
                rewrite_static,
                text
            )

    
            def fix_none_in_js(html: str) -> str:
                def repl(m): return m.group(0).replace("None", "null")
                return re.sub(r"<script.*?>.*?</script>", repl, html, flags=re.DOTALL | re.IGNORECASE)
            text = fix_none_in_js(text)

            fixed_spec_url = "http://localhost:9000/openapi/openapi.json"
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
            print(f"HTML rewrite error: {e}")

    headers_out = {
        "X-Proxy-Status": "proxied",
        "X-Proxy-Original-URL": raw_url,
        "X-Proxy-Final-URL": resp.url,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }

    return Response(content, status=resp.status_code, headers=headers_out, content_type=content_type)

# ---------------- Serve thumbnails ----------------
@app.route("/static/thumbs/<path:filename>")
def thumbs(filename):
    return send_from_directory(os.path.join(app.root_path, "static", "thumbs"), filename)

# ---------------- Main ----------------
if __name__ == "__main__":
    os.makedirs(os.path.join(app.root_path, "static", "thumbs"), exist_ok=True)
    app.run(host="0.0.0.0", port=8080)
