#!/usr/bin/env python3
"""
WordPress CVE Monitor for CodeVigilant Semgrep Rules

Checks NVD for new WordPress plugin/theme CVEs, analyzes the vulnerability
pattern against existing semgrep rules, and:
- If caught: comments on tracking issue with which rule(s) would detect it
- If NOT caught: generates a new semgrep rule and creates a PR

Runs every 4 hours via Hermes cron.

KEY INSIGHT: We cannot download "vulnerable" code from WordPress.org — only
the latest patched version is available. So we analyze the CVE DESCRIPTION
to extract the vulnerability pattern, then check if our existing rules cover
that pattern type. We only generate new rules for genuinely uncovered patterns.
"""

import csv
import html as html_lib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# Paths
REPO_DIR = Path("/root/WORK/codevigilant_semgrep_rules")
STATE_FILE = REPO_DIR / ".wp_cve_state.json"
SEMPEG_BIN = "/root/venv/bin/semgrep"
TRACKING_ISSUE = 1
RULES_DIR = REPO_DIR / "php"

# Monitoring windows
LOOKBACK_DAYS = 7          # NVD publication window
PATCHSTACK_MAX_AGE_H = 72  # Patchstack disclosures newer than this count as "new"
EXPLOITDB_LOOKBACK_DAYS = 21
PATCHSTACK_PAGES = 3       # 20 rows/page on https://patchstack.com/database/
MAX_LISTED = 15           # max findings listed per source section
DRY_RUN = os.environ.get("WP_MONITOR_DRY", "") == "1"


def gh_api_json(endpoint: str, json_data: str = None, method: str = "GET") -> dict:
    """Call GitHub API via gh CLI with JSON body."""
    cmd = ["gh", "api", endpoint, "--method", method]
    if json_data:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(json_data)
            tmp_path = f.name
        try:
            cmd.extend(["--input", tmp_path])
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        finally:
            os.unlink(tmp_path)
    else:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        print(f"[ERROR] gh api {endpoint}: {result.stderr.strip()}")
        return {}
    return json.loads(result.stdout) if result.stdout.strip() else {}


def load_state() -> dict:
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"processed_cves": [], "last_check": None}


def save_state(state: dict):
    state["last_check"] = datetime.now(timezone.utc).isoformat()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def http_get_json(url: str, headers: dict = None, timeout: int = 30) -> Optional[dict]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        print(f"[WARN] HTTP GET {url}: {e}")
        return None


# ─────────────────────────────────────────────
# CVE SOURCE: NVD API (WordPress plugin CVEs)
# ─────────────────────────────────────────────
def fetch_nvd_wordpress_cves() -> list:
    """Search NVD for recent WordPress plugin/theme CVEs.

    NOTE: the query intentionally does NOT use keywordExactMatch on
    "wordpress plugin" — the dominant Wordfence/Patchstack phrasing is
    "The Foo plugin for WordPress is vulnerable to ...", which that phrase
    filter silently dropped (~80% of published WordPress CVEs).
    We query all WordPress mentions in the window and filter on description.
    """
    vulns = []
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=LOOKBACK_DAYS)
    start_index = 0
    per_page = 2000
    total = None
    fetched = 0
    while True:
        query = urllib.parse.urlencode({
            "keywordSearch": "WordPress",
            "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
            "resultsPerPage": per_page,
            "startIndex": start_index,
        })
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + query
        data = http_get_json(url, timeout=60)
        if not data or "vulnerabilities" not in data:
            print("[WARN] NVD fetch failed at startIndex", start_index)
            break
        total = data.get("totalResults", 0)
        batch = data.get("vulnerabilities", [])
        fetched += len(batch)
        for v in batch:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            plugin_slug = extract_plugin_from_cve_desc(desc)
            vuln_type = classify_cve_type(cve)
            vuln_pattern = extract_vuln_pattern(desc, vuln_type)

            if plugin_slug and vuln_type != "unknown" and is_wp_extension_desc(desc):
                vulns.append({
                    "cve_id": cve_id,
                    "plugin_slug": plugin_slug,
                    "title": desc[:200],
                    "vuln_type": vuln_type,
                    "vuln_pattern": vuln_pattern,
                    "description": desc,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
        if fetched >= total or not batch:
            break
        start_index += len(batch)
    print(f"[INFO] NVD API: {len(vulns)} WordPress plugin/theme CVEs found")
    return vulns


WP_EXT_RE = re.compile(
    r"(?:plugin|theme)\s+(?:for\s+WordPress|for\s+the\s+WordPress)|"
    r"WordPress\s+(?:plugin|theme)|"
    r"WordPress\s+(?:plugin|theme)\s+(?:before|through|up\s+to)",
    re.IGNORECASE,
)


def is_wp_extension_desc(desc: str) -> bool:
    """True when the CVE description is about a WordPress plugin or theme."""
    if not desc:
        return False
    return bool(WP_EXT_RE.search(desc)) or (
        "wordpress" in desc.lower() and re.search(r"\b(?:plugin|theme)\b", desc, re.I) is not None
    )


def extract_plugin_from_cve_desc(desc: str) -> Optional[str]:
    """Extract WordPress plugin slug from CVE description."""
    patterns = [
        # Dominant Wordfence/WPScan phrasing:
        # "The Foo Bar plugin for WordPress is vulnerable to ..."
        r'\bThe\s+([A-Za-z0-9][A-Za-z0-9 \-\_&\.\,\+\u2013\u2014<>=]{1,90}?)\s+(?:plugin|theme)\s+for\s+WordPress',
        # "The Foo Bar <= 1.2.3 plugin ..." / "The Foo plugin (versions ...)"
        r'\bThe\s+([A-Za-z0-9][A-Za-z0-9 \-\_&\.\,\+\u2013\u2014<>=]{1,90}?)\s+(?:plugin|theme)\b',
        # "WordPress plugin "Foo" before 1.2"
        r'WordPress\s+plugin\s+[\"\'\u201c]([A-Za-z0-9 \-\_\.]{2,60})[\"\'\u201d]',
        # Multi-word names: "The Ultimate Member WordPress plugin before 2.12.1"
        r'(?:The\s+)?([A-Z][A-Za-z0-9]+(?:\s+[A-Za-z0-9]+){1,4})\s+WordPress\s+plugin\s+(?:before|through|up to|prior)',
        # "vulnerability in the Foo plugin" / "in Foo before 1.2"
        r'\bin\s+the\s+([A-Za-z0-9][A-Za-z0-9 \-\_&\.\,\+\u2013\u2014<>=]{1,70}?)\s+plugin\b',
    ]
    false_positives = {
        'before', 'through', 'to', 'the', 'and', 'or', 'in', 'on',
        'for', 'with', 'from', 'that', 'this', 'has', 'was', 'are',
        'not', 'may', 'can', 'could', 'would', 'should', 'will',
        'wordpress', 'plugin', 'theme', 'vulnerability', 'vulnerabilities',
        'allowing', 'allow', 'remote', 'local', 'file', 'code', 'attack',
        # junk captured by loose patterns
        'versions', 'version', 'files', 'file', 'approve', 'up', 'includes',
        'including', 'order', 'orders', 'is', 'it', 'its', 'their', 'a', 'an',
        'following', 'certain', 'some', 'these', 'those', 'which', 'when',
        'authenticated', 'unauthenticated', 'subscriber', 'contributor',
    }
    for pattern in patterns:
        match = re.search(pattern, desc, re.IGNORECASE)
        if match:
            slug = match.group(1).lower().strip()
            # Drop a trailing version only when it actually looks like one (has a dot)
            slug = re.sub(r'\s*(?:<=\s*)?v?\d+(?:\.\d+)+\S*$', '', slug).strip(' .-\u2013\u2014&')
            # Cut marketing taglines: 'Nelio Content - Editorial Calendar' -> 'nelio-content'
            slug = re.split(r'\s+[\u2013\u2014]\s+|\s+-\s+|\s*\u0026\s*', slug)[0].strip()
            # Normalize multi-word names to kebab-case (e.g. "Ultimate Member" -> "ultimate-member")
            slug = re.sub(r'\s+', '-', slug)
            # Drop a captured leading article ("The GiveWP" -> "givewp")
            if slug.startswith('the-') and len(slug) > 5:
                slug = slug[4:]
            # Drop a trailing "wordpress" captured inside a multi-word name
            slug = re.sub(r'(-wordpress|-plugin)$', '', slug)
            if slug in false_positives or len(slug) < 3:
                continue
            if re.fullmatch(r'[\d\.\-]+', slug):
                continue
            return slug
    return None


def classify_cve_type(cve: dict) -> str:
    """Classify vulnerability type from CVE data."""
    desc_text = " ".join(
        d.get("value", "")
        for d in cve.get("descriptions", [])
        if d.get("lang") == "en"
    ).lower()

    type_keywords = {
        "sql_injection": ["sql injection", "sqli", "blind sql"],
        "xss": ["cross-site scripting", "xss", "reflected xss", "stored xss",
                "does not sanitise", "does not sanitize", "does not escape",
                "store javascript", "javascript that runs", "unfiltered_html"],
        "rce": ["remote code execution", "rce", "command injection", "code injection"],
        "ssrf": ["server-side request forgery", "ssrf"],
        "lfi": ["local file inclusion", "path traversal", "directory traversal"],
        "file_deletion": ["arbitrary file deletion", "arbitrary file delete",
                          "file deletion", "deletes arbitrary files"],
        "rfi": ["remote file inclusion"],
        "deserialization": ["deserialization", "insecure deserialization", "unserialize"],
        "csrf": ["cross-site request forgery", "csrf", "nonce check", "nonce checks",
                 "capability or nonce", "nonce"],
        "privilege_escalation": ["privilege escalation", "authentication bypass",
                                 "privilege", "capability check", "missing authorization",
                                 "missing authentication", "capabilit", "elevat",
                                 "administrator-level"],
        "idor": ["broken access control", "does not verify that", "does not restrict access",
                 "does not properly restrict", "does not verify", "does not restrict",
                 "belongs to the requesting user", "authorized to modify",
                 "access control", "does not check that"],
        "information_disclosure": ["information disclosure", "publicly accessible",
                                   "predictable filename", "predictable location",
                                   "backup archives", "export files",
                                   "without access protection", "does not protect"],
        "auth_bypass": ["one-time password", "otp", "does not validate the submitted",
                        "stored secret", "authentication bypass"],
    }
    for vuln_type, keywords in type_keywords.items():
        for kw in keywords:
            # Short tokens ("rce", "otp", "xss") must match whole words — plain
            # substring matching classified "source" as RCE ("...rce").
            if len(kw) <= 6 and re.fullmatch(r"[a-z0-9_-]+", kw):
                if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", desc_text):
                    return vuln_type
            elif kw in desc_text:
                return vuln_type
    return "unknown"


def extract_vuln_pattern(desc: str, vuln_type: str) -> str:
    """Extract the specific vulnerable code pattern from CVE description."""
    desc_lower = desc.lower()

    patterns = {
        "sql_injection": [
            (r'(?:(?:prepare|query|execute)\s*\(|wpdb)', "wpdb query without proper preparation"),
            (r'(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE).*(?:query|sql|prepare)', "user input in SQL query"),
            (r'(?:UNION|SELECT|INSERT|UPDATE|DELETE)\s+(?:ALL\s+)?SELECT', "UNION-based SQL injection"),
        ],
        "xss": [
            (r'(?:echo|print|printf|vprintf)\s+.*\$_(?:GET|POST|REQUEST|COOKIE)', "unescaped output of user input"),
            (r'(?:innerHTML|document\.write|eval\s*\()', "dangerous JavaScript sink"),
            (r'(?:esc_html|esc_attr|esc_url|wp_kses).*\$_(?:GET|POST|REQUEST)', "insufficient escaping"),
            (r'(?:admin_page|admin_notices|settings_page).*\$_', "reflected input in admin page"),
        ],
        "rce": [
            (r'(?:eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\(', "dangerous function call"),
            (r'(?:file_get_contents|file_put_contents|fopen|fwrite)\s*\(.*\$_', "file operation with user input"),
            (r'(?:call_user_func|array_map|array_filter)\s*\(.*\$_', "callback with user input"),
            (r'(?:unserialize|wp_unserialize)\s*\(.*\$_', "deserialization of user input"),
        ],
        "ssrf": [
            (r'(?:file_get_contents|fopen|curl_setopt|wp_remote_get|wp_remote_post)\s*\(.*\$_', "HTTP request with user-controlled URL"),
            (r'(?:get_headers|getimagesize)\s*\(.*\$_', "network function with user input"),
        ],
        "lfi": [
            (r'(?:include|require|include_once|require_once)\s*\(.*\$_', "file inclusion with user input"),
            (r'(?:file_get_contents|fopen|readfile)\s*\(.*\$_', "file read with user input"),
            (r'(?:path|directory|folder).*\.\.\/', "path traversal"),
        ],
        "csrf": [
            (r'(?:wp_ajax|admin_post|admin_init).*\$_(?:POST|GET)', "AJAX handler without nonce check"),
            (r'(?:\$_POST|\$_GET).*(?:create|update|delete|remove)', "state-changing operation without nonce"),
        ],
        "privilege_escalation": [
            (r'(?:current_user_can|user_can|is_super_admin).*\$_', "capability check with user input"),
            (r'(?:update_option|add_option|delete_option)\s*\(.*\$_', "option modification without proper check"),
            (r'(?:wp_insert_user|wp_update_user|wp_delete_user)\s*\(.*\$_', "user manipulation without capability check"),
        ],
        "deserialization": [
            (r'(?:unserialize)\s*\(.*\$_', "deserialization of user input"),
            (r'(?:maybe_unserialize)\s*\(.*\$_', "WordPress unserialization of user input"),
        ],
        "idor": [
            (r'(?:does not (?:verify|check|restrict|properly restrict))', "missing ownership/authorization verification"),
            (r'(?:belongs to the requesting user|authorized to modify)', "missing object-level authorization"),
        ],
        "information_disclosure": [
            (r'(?:publicly accessible|predictable filename|predictable location)', "sensitive files in predictable/public location"),
            (r'(?:backup archives|export files)', "sensitive backup/export file exposure"),
        ],
        "auth_bypass": [
            (r'(?:one-time password|stored secret|otp)', "weak/incorrect OTP verification"),
            (r'(?:does not validate)', "missing credential validation"),
        ],
    }

    type_patterns = patterns.get(vuln_type, [])
    for regex, pattern_desc in type_patterns:
        if re.search(regex, desc_lower):
            return pattern_desc

    return f"generic {vuln_type} pattern"


# ─────────────────────────────────────────────
# SOURCE 2: Patchstack vulnerability database (disclosures, incl. non-CVE)
# ─────────────────────────────────────────────
PS_ROW_RE = re.compile(r'<tr class="group.*?</tr>', re.S)
PS_LINK_RE = re.compile(
    r'href="/database/wordpress/(plugin|theme)/([^/"]+)/vulnerability/([^"]+)"')
REL_TIME_RE = re.compile(
    r'(\d+)\s*(minute|min|hour|hr|day|week)s?\s+ago|(\d{2})/(\d{2})/(\d{4})', re.I)


def _fetch_html(url: str, timeout: int = 45) -> str:
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[WARN] HTTP GET {url}: {e}")
        return ""


def _age_hours(txt: str):
    """Parse '3 hours ago' / '04/12/2026' into age in hours (None if unknown)."""
    m = REL_TIME_RE.search(txt)
    if not m:
        return None
    if m.group(1):
        n, unit = int(m.group(1)), m.group(2).lower()
        return n * {"minute": 1 / 60, "min": 1 / 60, "hour": 1,
                    "hr": 1, "day": 24, "week": 168}[unit]
    d, mo, y = int(m.group(3)), int(m.group(4)), int(m.group(5))
    try:
        dt = datetime(y, mo, d, tzinfo=timezone.utc)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds() / 3600


def _kw_hit(text: str, kw: str) -> bool:
    """Keyword match that keeps short tokens ('rce', 'xss') on word boundaries.

    Plain substring matching classified "WooCommerce" / "source" as RCE.
    """
    if len(kw) <= 6 and re.fullmatch(r"[a-z0-9_-]+", kw):
        return re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", text) is not None
    return kw in text


def classify_text_type(text: str) -> str:
    """Classify vulnerability type from an advisory title."""
    t = text.lower()
    ordered = [
        ("sql_injection", ["sql injection", "sqli"]),
        ("deserialization", ["deserialization", "unserialize", "object injection"]),
        ("rce", ["remote code execution", "rce", "code execution", "command injection",
                 "code injection", "arbitrary file upload", "file upload"]),
        ("ssrf", ["server-side request forgery", "ssrf"]),
        ("file_deletion", ["arbitrary file deletion", "file deletion", "delete files",
                           "unlink"]),
        ("lfi", ["local file inclusion", "path traversal", "directory traversal",
                 "file inclusion"]),
        ("xss", ["cross-site scripting", "xss"]),
        ("csrf", ["cross-site request forgery", "csrf"]),
        ("idor", ["insecure direct object reference", "idor",
                  "broken access control", "missing authorization",
                  "missing capability", "arbitrary post", "arbitrary option"]),
        ("privilege_escalation", ["privilege escalation", "subscriber", "contributor",
                                  "admin+", "authentication bypass",
                                  "broken authentication"]),
        ("information_disclosure", ["sensitive information", "information disclosure",
                                    "information exposure", "exposure of sensitive"]),
        ("auth_bypass", ["otp", "one-time password", "password reset"]),
        ("subscriber_data_access", ["export", "backup"]),
    ]
    for vtype, kws in ordered:
        if any(_kw_hit(t, k) for k in kws):
            return vtype
    return "unknown"


def fetch_patchstack_disclosures() -> list:
    """Scrape the Patchstack database listing (most recent disclosures first)."""
    out = []
    for page in range(1, PATCHSTACK_PAGES + 1):
        url = "https://patchstack.com/database/" + (f"?page={page}" if page > 1 else "")
        html = _fetch_html(url)
        if not html:
            continue
        rows = PS_ROW_RE.findall(html)
        print(f"[INFO] Patchstack page {page}: {len(rows)} rows")
        for row in rows:
            link = PS_LINK_RE.search(row)
            if not link:
                continue
            kind, slug, vuln_path = link.group(1), link.group(2), link.group(3)
            text = re.sub(r"<[^>]+>", " ", row)
            text = re.sub(r"\s+", " ", html_lib.unescape(text)).strip()
            age_h = _age_hours(text)
            if age_h is None or age_h > PATCHSTACK_MAX_AGE_H:
                continue
            title = PS_TITLE_RE.sub(" ", text.split("vulnerability")[0]).strip()
            title = re.sub(r"\s+", " ", title).strip(" |")
            exploited = bool(re.search(r"exploited in the wild|actively exploited", text, re.I))
            version = (re.search(r"<=\s*([\w\.\-]+)", title) or [None, ""])[1]
            out.append({
                "id": f"PATCHSTACK-{slug}-{vuln_path[:60]}",
                "plugin_slug": slug,
                "kind": kind,
                "title": title,
                "display": f"{slug} {version}".strip(),
                "vuln_type": classify_text_type(title),
                "age_hours": round(age_h, 1),
                "is_exploited": exploited,
                "url": f"https://patchstack.com/database/wordpress/{kind}/{slug}/vulnerability/{vuln_path}",
                "source": "patchstack",
            })
    print(f"[INFO] Patchstack: {len(out)} disclosures within {PATCHSTACK_MAX_AGE_H}h")
    return out


PS_TITLE_RE = re.compile(r"^\s*[\d.]+\s*")


# ─────────────────────────────────────────────
# SOURCE 3: Exploit-DB (public exploit code)
# ─────────────────────────────────────────────
def fetch_exploitdb_wordpress() -> list:
    """Recent Exploit-DB entries that target WordPress plugins/themes."""
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    csv_text = _fetch_html(url, timeout=120)
    if not csv_text:
        print("[WARN] Exploit-DB CSV unavailable")
        return []
    out = []
    today = datetime.now(timezone.utc).date()
    for r in csv.DictReader(io.StringIO(csv_text)):
        d = None
        for field in ("date_added", "date_published"):
            try:
                d = datetime.strptime((r.get(field) or "").strip(), "%Y-%m-%d").date()
                break
            except ValueError:
                continue
        if not d or (today - d).days > EXPLOITDB_LOOKBACK_DAYS:
            continue
        blob = " ".join((r.get(k) or "") for k in ("description", "tags", "file", "platform")).lower()
        if "wordpress" not in blob and "woocommerce" not in blob:
            continue
        out.append({
            "id": f"EDB-{r.get('id')}",
            "plugin_slug": (r.get("description") or "")[:60],
            "title": r.get("description", ""),
            "vuln_type": classify_text_type(r.get("description", "")),
            "date": str(d),
            "url": f"https://www.exploit-db.com/exploits/{r.get('id')}",
            "source": "exploitdb",
            "is_exploited": True,
        })
    print(f"[INFO] Exploit-DB: {len(out)} WordPress exploits in last {EXPLOITDB_LOOKBACK_DAYS}d")
    return out


# ─────────────────────────────────────────────
# EXISTING RULE ANALYSIS
# ─────────────────────────────────────────────
def load_existing_rules() -> dict:
    """Load all existing semgrep rules and index them by category."""
    rules = {}
    for yaml_file in RULES_DIR.rglob("*.yaml"):
        try:
            with open(yaml_file) as f:
                content = f.read()
            # Extract rule IDs
            ids = re.findall(r'-\s*id:\s*(.+)', content)
            # Extract patterns
            patterns = re.findall(r'-\s*pattern(?:-regex)?:\s*(.+)', content)
            # Determine category from path
            rel_path = str(yaml_file.relative_to(RULES_DIR))
            category = rel_path.split('/')[0] if '/' in rel_path else 'root'
            subcategory = rel_path.split('/')[1] if len(rel_path.split('/')) > 1 else 'root'

            for rule_id in ids:
                rule_id = rule_id.strip()
                rules[rule_id] = {
                    "file": str(yaml_file),
                    "patterns": patterns,
                    "category": category,
                    "subcategory": subcategory,
                    "path": rel_path,
                }
        except Exception as e:
            print(f"[WARN] Could not parse {yaml_file}: {e}")
    return rules


def analyze_coverage(vuln_type: str, vuln_pattern: str, existing_rules: dict) -> dict:
    """Determine if existing rules would catch this vulnerability pattern."""
    # Map vuln types to rule categories that should cover them
    category_mapping = {
        # rule_patterns are substrings of real rule ids (php/**/*.yaml); they are
        # the only coverage signal — keep them in sync with the rule inventory.
        "sql_injection": {
            "rule_patterns": ["sqli", "wpdb", "direct_db_query"],
            "pattern_keywords": ["wpdb", "query", "prepare", "sql"],
        },
        "xss": {
            "rule_patterns": ["xss"],
            "pattern_keywords": ["echo", "print", "esc_html", "esc_attr"],
        },
        "rce": {
            "rule_patterns": ["rce", "dynamic_function_call", "call_user_func_user_input",
                              "create_function"],
            "pattern_keywords": ["eval", "exec", "system", "passthru", "shell_exec"],
        },
        "ssrf": {
            "rule_patterns": ["ssrf"],
            "pattern_keywords": ["file_get_contents", "curl", "wp_remote", "fsockopen"],
        },
        "lfi": {
            "rule_patterns": ["lfi", "dynamic_include"],
            "pattern_keywords": ["include", "require", "path", "directory"],
        },
        "file_deletion": {
            "rule_patterns": ["file_deletion", "unlink", "wp_delete_file"],
            "pattern_keywords": ["unlink", "delete file"],
        },
        "csrf": {
            "rule_patterns": ["csrf", "nonce"],
            "pattern_keywords": ["nonce", "verify", "wp_nonce"],
        },
        "privilege_escalation": {
            "rule_patterns": ["auth.", "capabilit", "global_override"],
            "pattern_keywords": ["capability", "role", "privilege"],
        },
        "deserialization": {
            "rule_patterns": ["deserial", "unserialize"],
            "pattern_keywords": ["unserialize", "maybe_unserialize"],
        },
        "idor": {
            "rule_patterns": ["auth.", "current_user_can", "capabilit"],
            "pattern_keywords": ["capability", "current_user_can", "authorization"],
        },
        "information_disclosure": {
            "rule_patterns": ["info_disclosure", "information"],
            "pattern_keywords": ["phpinfo", "var_dump", "print_r", "backtrace"],
        },
        "auth_bypass": {
            "rule_patterns": ["auth.", "password", "login"],
            "pattern_keywords": ["auth", "login", "otp"],
        },
    }
    mapping = category_mapping.get(vuln_type, {})
    if not mapping:
        return {"covered": False, "coverage_type": "no_mapping", "matching_rules": []}

    relevant_patterns = mapping.get("rule_patterns", [])
    relevant_keywords = mapping.get("pattern_keywords", [])

    # Find rules that match this vulnerability type by rule-id substring.
    # NOTE: an earlier version also matched free-text patterns scraped from the
    # whole YAML file, which made nearly every finding look "strongly covered"
    # (e.g. RCE matching sqli rules). Rule-id matching is the honest signal.
    matching_rules = []
    for rule_id in existing_rules:
        if any(p in rule_id.lower() for p in relevant_patterns):
            matching_rules.append(rule_id)

    # Determine coverage quality
    if len(matching_rules) >= 3:
        coverage = "strong"
    elif len(matching_rules) >= 1:
        coverage = "partial"
    else:
        coverage = "none"

    return {
        "covered": len(matching_rules) > 0,
        "coverage_type": coverage,
        "matching_rules": matching_rules[:10],  # Limit for readability
    }


# ─────────────────────────────────────────────
# TRACKING ISSUE COMMENT
# ─────────────────────────────────────────────
def render_item(vuln: dict, coverage: dict) -> str:
    """One markdown bullet describing an analysed item."""
    label = vuln.get("cve_id") or vuln.get("display") or vuln.get("id", "?")
    flag = " 🚨 **ACTIVELY EXPLOITED**" if vuln.get("is_exploited") else ""
    slug = vuln.get("plugin_slug", "?")
    vtype = vuln.get("vuln_type", "unknown")
    line = f"- **{label}** — `{slug}` ({vtype}){flag}\n"
    if vuln.get("vuln_pattern"):
        line += f"  - Pattern: {vuln['vuln_pattern']}\n"
    if vuln.get("title") and vuln.get("source") != "nvd":
        title = re.sub(r"\s+", " ", str(vuln["title"]))[:120]
        line += f"  - Advisory: {title}\n"
    if coverage:
        rules = ", ".join(f"`{r}`" for r in coverage["matching_rules"][:3])
        line += (f"  - Coverage: {coverage['coverage_type']} "
                 f"({len(coverage['matching_rules'])} rules)"
                 + (f" — {rules}" if rules else "") + "\n")
    if vuln.get("url"):
        line += f"  - Source: <{vuln['url']}>\n"
    return line


def update_tracking_issue(sections: dict, counts: dict):
    """Add one comment to the tracking issue, broken out per source channel."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = f"## 📊 WP Vuln Monitor — {timestamp}\n\n"
    body += (f"**New items**: {counts['total']} "
             f"(NVD {counts['nvd']} · Patchstack {counts['patchstack']} · Exploit-DB {counts['edb']})  \n")
    body += f"**Caught by existing rules**: {counts['caught']}  \n"
    body += f"**Not covered (new rules needed)**: {counts['missed']}\n"

    titles = {
        "nvd": "1️⃣ NVD CVEs",
        "patchstack": "2️⃣ Patchstack disclosures",
        "exploitdb": "3️⃣ Exploit-DB exploits",
    }
    for key in ("nvd", "patchstack", "exploitdb"):
        items = sections.get(key, [])
        if not items:
            body += f"\n### {titles[key]}\n\n_None new in this cycle._\n"
            continue
        caught = [i for i in items if i["coverage"]["covered"]]
        missed = [i for i in items if not i["coverage"]["covered"]]
        exploited = [i for i in items if i["vuln"].get("is_exploited")]
        type_counts = {}
        for i in items:
            t = i["vuln"].get("vuln_type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        summary = ", ".join(f"{t} {n}" for t, n in sorted(type_counts.items(), key=lambda x: -x[1]))
        body += f"\n### {titles[key]} — {len(items)} new\n\n"
        body += f"_By type: {summary}_\n\n"

        # Uncovered + exploited are always listed; covered items are sampled to
        # keep the comment under GitHub's size limit on busy days.
        show = missed + [i for i in exploited if i not in missed][:MAX_LISTED]
        if show:
            body += "**❌ Not covered / actively exploited**\n\n"
            body += "".join(render_item(i["vuln"], i["coverage"] if i["coverage"]["covered"] else None)
                            + "\n" for i in show)
        remaining = [i for i in caught if i not in show]
        if remaining:
            body += f"**✅ Covered by existing rules** ({len(remaining)})\n\n"
            body += "".join(render_item(i["vuln"], i["coverage"]) + "\n"
                            for i in remaining[:MAX_LISTED])
            if len(remaining) > MAX_LISTED:
                body += f"\n_…and {len(remaining) - MAX_LISTED} more covered findings (all recorded in monitor state)._\n"

    body += "\n---\n*Auto-generated by WordPress Vulnerability Monitor (NVD + Patchstack + Exploit-DB)*\n"

    if DRY_RUN:
        Path("/tmp/comment_body.md").write_text(body)
        print(f"[DRY] comment body chars={len(body)} -> /tmp/comment_body.md")
        return
    comment = gh_api_json(
        f"repos/ai-anant/codevigilant_semgrep_rules/issues/{TRACKING_ISSUE}/comments",
        json.dumps({"body": body}),
        method="POST",
    )
    if comment:
        print(f"[INFO] Added comment to issue #{TRACKING_ISSUE}")


# ─────────────────────────────────────────────
# MAIN WORKFLOW
# ─────────────────────────────────────────────
def main():
    print(f"[INFO] WordPress Vulnerability Monitor starting at "
          f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    state = load_state()
    processed = set(state.get("processed_cves", []))
    seen_disc = set(state.get("seen_disclosures", []))
    seen_expl = set(state.get("seen_exploits", []))

    # ── 1. Collect from all three channels ──────────────────────────────
    nvd_all = fetch_nvd_wordpress_cves()
    ps_all = fetch_patchstack_disclosures()
    edb_all = fetch_exploitdb_wordpress()

    new_nvd, new_ps, new_edb = [], [], []
    seen_ids = set()
    for v in nvd_all:
        cid = v.get("cve_id", "")
        if cid and cid not in processed and cid not in seen_ids:
            seen_ids.add(cid)
            v["source"] = "nvd"
            v["cve_id"] = cid
            new_nvd.append(v)

    seen_ids.clear()
    for d in ps_all:
        did = d["id"]
        # A disclosure whose CVE was already reported via NVD is not "new"
        if did in seen_disc or did in seen_ids:
            continue
        seen_ids.add(did)
        new_ps.append(d)

    seen_ids.clear()
    for e in edb_all:
        eid = e["id"]
        if eid in seen_expl or eid in seen_ids:
            continue
        seen_ids.add(eid)
        new_edb.append(e)

    total_new = len(new_nvd) + len(new_ps) + len(new_edb)
    print(f"[INFO] New: NVD={len(new_nvd)} Patchstack={len(new_ps)} Exploit-DB={len(new_edb)}")

    if not total_new:
        print("[INFO] No new WordPress CVEs / disclosures / exploits detected in this cycle.")
        save_state(state)
        return

    # ── 2. Coverage analysis ────────────────────────────────────────────
    existing_rules = load_existing_rules()
    print(f"[INFO] Loaded {len(existing_rules)} existing rules")

    def analyse(items):
        out = []
        for v in items:
            vtype = v.get("vuln_type", "unknown")
            cov = analyze_coverage(vtype, v.get("vuln_pattern", ""), existing_rules)
            status = "CAUGHT" if cov["covered"] else "MISSED"
            print(f"  {'✅' if cov['covered'] else '❌'} {v.get('cve_id') or v.get('id')} "
                  f"[{vtype}] -> {status} ({cov['coverage_type']}, {len(cov['matching_rules'])} rules)")
            out.append({"vuln": v, "coverage": cov})
        return out

    sections = {
        "nvd": analyse(new_nvd),
        "patchstack": analyse(new_ps),
        "exploitdb": analyse(new_edb),
    }
    flat = [i for s in sections.values() for i in s]
    caught_n = sum(1 for i in flat if i["coverage"]["covered"])

    # ── 3. Report ───────────────────────────────────────────────────────
    update_tracking_issue(sections, {
        "total": total_new,
        "nvd": len(new_nvd),
        "patchstack": len(new_ps),
        "edb": len(new_edb),
        "caught": caught_n,
        "missed": len(flat) - caught_n,
    })

    # ── 4. Persist state ────────────────────────────────────────────────
    processed.update(v["cve_id"] for v in new_nvd)
    seen_disc.update(d["id"] for d in new_ps)
    seen_expl.update(e["id"] for e in new_edb)
    state["processed_cves"] = sorted(processed)
    state["seen_disclosures"] = sorted(seen_disc)
    state["seen_exploits"] = sorted(seen_expl)
    if DRY_RUN:
        print("[DRY] state not saved")
    else:
        save_state(state)

    print("\n[DONE]")
    print(f"  - analysed: {total_new} (NVD {len(new_nvd)}, Patchstack {len(new_ps)}, EDB {len(new_edb)})")
    print(f"  - caught: {caught_n}   not covered: {len(flat) - caught_n}")
    for i in flat:
        if not i["coverage"]["covered"]:
            v = i["vuln"]
            print(f"    MISSED {v.get('cve_id') or v.get('id')}: "
                  f"{v.get('plugin_slug')} ({v.get('vuln_type')})")


if __name__ == "__main__":
    main()
