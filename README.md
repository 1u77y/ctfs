# SSRF → SSTI → RCE → LPE Simulation

---

## Overview

This is a **safe, contained Boot2Root simulation** teaching chained exploitation techniques:

**SSRF → SSTI → simulated RCE → LPE**

---

## Services

| Service    | URL / Port              | Description                                                      |
| ---------- | ----------------------- | ---------------------------------------------------------------- |
| public-app | `http://localhost`      | Image gallery using `/fetch?url=...`. Proxy internal requests.   |
| admin-api  | `http://localhost:9000` | Admin endpoints: `/admin`, `/status`, `/render`, `/render/json`. |

> Players must use the gallery `/fetch` proxy — direct access to `:9000` is blocked.

---

## Goals

1. Discover SSRF on gallery `/fetch?url=<internal-url>`.
2. Find admin routes: `/admin`, `/status`, `/render`, `/render/json`.
3. Exploit **safe SSTI** at `/render/json` (Jinja2), avoiding forbidden keywords (see below).
4. Simulate **Privilege Escalation**: `monkey` → `shelldon` → read final flag.

**Flags:**

* Low-priv: `SADC{render_pipeline_owned_by_you_kudos_and_tears}`
* Final: `SADC{chained_exploit_ssrf_ssti_rce_lpe}`

---

## Forbidden keywords

```python
FORBIDDEN_KEYWORDS = [
    "config", "request", "self", "cycler", "__class__",
    "os", "subprocess", "__subclasses__", "eval", "exec",
    "import", "builtins"
]
```

Payloads containing those exact substrings will be blocked. Players must think creatively to bypass filters within the safe constraints.

---

## Quick enumeration (encoded URL rule)

**Important:** All internal probes must use the *encoded* `fetch` URL. Non‑encoded direct URLs will not work.

Format example (URL-encoded target):

```
http://localhost/fetch?url=http%3A%2F%2Flocalhost%3A9000%2Fadmin
```

Use the provided scripts to produce properly encoded requests.

---

## Simplified Enumeration Script (Bash)

```bash
#!/bin/bash
# simple_scan.sh - probes internal ports and paths via /fetch proxy

HOST="localhost"
PROXY="http://localhost/fetch?url="
PORTS=(9000 8080)
PATHS=("/" "/admin" "/status" "/render" "/render/json")

for PORT in "${PORTS[@]}"; do
  for PATH in "${PATHS[@]}"; do
    TARGET="http://${HOST}:${PORT}${PATH}"
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$TARGET', safe=''))")
    URL="${PROXY}${ENCODED}"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${URL}")
    echo "Proxied ${TARGET} => HTTP ${STATUS}"
  done
done
```

> Save as `simple_scan.sh` and run with:
> `chmod +x simple_scan.sh && ./simple_scan.sh`

---

## Simplified Enumeration Script (Python)

```python
#!/usr/bin/env python3
import urllib.parse
import requests

HOST = "localhost"
PORTS = [9000, 8080]
PATHS = ["/", "/admin", "/status", "/render", "/render/json"]
PROXY = "http://localhost/fetch?url="

for port in PORTS:
    for path in PATHS:
        target = f"http://{HOST}:{port}{path}"
        encoded = urllib.parse.quote(target, safe="")
        url = PROXY + encoded
        try:
            r = requests.get(url, timeout=5)
            print(f"Proxied {target} => HTTP {r.status_code}")
        except requests.RequestException as e:
            print(f"Proxied {target} => ERROR {e}")
```

> Run with: `python3 simple_scan.py`

---

## Enumeration hints you should surface to players

1. **Only encoded URLs work.** Highlight that `http://localhost/fetch?url=<encoded-target>` is the only accepted way to reach internal services.
2. **Look for a documentation endpoint** — the challenge exposes an OpenAPI/Swagger doc at the proxied documentation URL, accessible through the proxy (example):
   `http://localhost/fetch?url=http%3A%2F%2Flocalhost%3A9000%2Fopenapi%2Fswagger`
   (Players should use their proxy to fetch that URL.)
3. The OpenAPI doc page lists routes such as `/render`, `/status`, `/template/get`, and `/template/list`. **Primary focus:** `/render`.
4. **Check `/admin` — small note only.** The `/admin` page contains a single admin note:

   > NOTES: Oops we left a documentation file . Those who look beyond the surface might find hidden paths.

   This note is intentionally terse. Also, a documentation file was left during the app build and is retrievable via the proxied OpenAPI/Swagger endpoint — players who fetch the docs may discover additional path names or implementation details.
5. `/render` shows a page where previewing Jinja2 template is possible and where preview page templates are embedded in HTML — **this is a rabbit hole**: injections there will be rendered inside HTML and typically won’t allow command execution. Players must inspect the page to find the API endpoint used by the preview.
6. Inspect the preview to find the backend API path `http://localhost:9000/render/json` (the API endpoint used by the preview). That is the **real** SSTI target; players must send their template payloads to this API **via the encoded proxy**:
   `http://localhost/fetch?url=http%3A%2F%2Flocalhost%3A9000%2Frender%2Fjson`
7. The `/render/json` endpoint accepts a JSON body with fields such as `image_url` and `template`. SSTI here is possible, but **RCE is simulated**. The challenge requires bypassing the forbidden‑keywords filter; players will have to craft a payload that avoids those substrings.

---

## Logical Process (clear, step‑by‑step)

This section enforces a clear logical flow for players. Each step includes the action, what to inspect, expected indicators, and the checkpoint to move forward.

### Step 0 — Prerequisites

* Have the challenge environment running locally (containers/services started).
* Use only the encoded proxy URL form: `http://localhost/fetch?url=<url-encoded-target>`.

---

### Step 1 — Discovery (SSRF enumeration)

**Action:** Run the enumeration scripts (bash or python).
**What to inspect:** HTTP response codes and returned content for proxied targets.
**Expected indicators:** 200/403/404 responses; admin pages should be reachable through the proxy.
**Checkpoint:** You find a reachable admin page (e.g., `http://localhost/fetch?url=.../admin`) or the OpenAPI page.

---

### Step 2 — Inspect `/admin` and the docs

**Action:** Open `/admin` via the proxy and read the single admin note, then fetch the OpenAPI doc.
**What to inspect:** Page text, comments, admin note. `/admin` intentionally contains the short note shown above; wich might give players clue that a OpenAPI doc was left during build and can reveal route names or examples.
**Expected indicators:** Admin note`.
**Checkpoint:** Confirm routes from docs and identify `/render` and `/render/json`.

---

### Step 3 — Preview rabbit hole (render HTML)

**Action:** Open `/render` via the proxy.
**What to inspect:** Page source, embedded templates, network calls (browser devtools).
**Expected indicators:** A forgotten comment which reveal /render/json api path and parameters accepted.
**Checkpoint:** link to `http://localhost:9000/render/json` (the real SSTI target).

> Note: Direct template injection into the preview HTML is intentionally a rabbit hole — injections there may be sanitized or only affect the page context and not execute commands.

---

### Step 4 — Target the API (SSTI on `/render/json`)

**Action:** Send a JSON POST to `/render/json` **through the encoded proxy** with fields such as `image_url` and `template`.
**Proxy example:** `http://localhost/fetch?url=http%3A%2F%2Flocalhost%3A9000%2Frender%2Fjson`
**What to inspect:** Response body for rendered output or simulated command output.
**Expected indicators:** Rendered template output in the response. For learning, the challenge should return a simulated marker like `SADC{rce_test}` or similar when a payload executes an allowed safe command.
**Checkpoint:** You receive a simulated command output demonstrating SSTI success (low‑priv access).

---

### Step 5 — Low‑priv foothold (monkey)

**Action:** Use the simulated RCE output to confirm you are inside as `monkey`.
**What to inspect:** Files, sandboxed outputs, or markers returned by the challenge.
**Expected indicators:** Access to a low‑priv flag visible only to `monkey`:

```
SADC{render_pipeline_owned_by_you_kudos_and_tears}
```

**Checkpoint:** Low flag obtained — continue to local privesc simulation.

---

### Step 6 — Local privilege escalation (simulated)

**Action:** Perform the challenge's local privesc steps (these are simulated / environment‑specific). The CTF should provide escalations that require reasoning (config files, weak permissions, scheduled tasks), not real exploitation instructions in public docs.
**What to inspect:** Clues in file contents, logs, or services that indicate how to pivot from `monkey` to `shelldon`.
**Expected indicators:** Evidence that `shelldon` credentials or a vector is available after completing local tasks. On success, reveal the final flag:

```
SADC{chained_exploit_ssrf_ssti_rce_lpe}
```

**Checkpoint:** Final flag obtained — challenge complete.

---

## Safe (non‑actionable) SSTI demonstration payload

> **Security note:** The challenge contains an intentional SSTI vulnerability for learning. Below is a **redacted / safe** example that demonstrates the structure without executing network connections. Do **not** include real reverse‑shell commands in public docs.

```json
{
  "image_url": null,
  "template": "{{ joiner.__init__.__globals__['__buil'+'tins__']['__im' + 'port__']('o' + 's').popen('echo SADC{rce_test}').read() }}"
}
```

*This example prints `SADC{rce_test}` to demonstrate the concept without creating a network connection.* The challenge runtime can be configured to run safe commands or read sandboxed files that return the low‑priv flag.

---

## Hints / Checkpoints (for players)

* **Hint 1 :** Only encoded fetch URLs will reach internal services.
* **Hint 2 : ** The preview UI is a rabbit hole; the real SSTI target is a JSON API endpoint.
* **Extra hint:** Check `/admin` text and notes — admin notes often reference hidden paths or give clues to additional routes.
* **Final nudge:** Forbidden substrings are blocked — think about substring concatenation or using indirect lookups *within the safe constraints*.

---

