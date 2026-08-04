#!/usr/bin/env python3
"""
WordPress CVE Monitor for CodeVigilant Semgrep Rules

Checks multiple sources for new WordPress plugin/theme CVEs,
downloads affected source code, runs semgrep to detect coverage,
and creates PRs for missed detections + comments on tracking issue.

Runs every 4 hours via Hermes cron.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# Paths
REPO_DIR = Path("/root/WORK/codevigilant_semgrep_rules")
STATE_FILE = REPO_DIR / ".wp_cve_state.json"
SEMPEG_BIN = "/root/venv/bin/semgrep"
TRACKING_ISSUE = 1  # The tracking matrix issue
RULES_DIR = REPO_DIR / "php"
SCAN_CACHE = REPO_DIR / ".scan_cache"
SCAN_CACHE.mkdir(exist_ok=True)

# WordPress.org API
WP_ORG_API = "https://api.wordpress.org/plugins/info/1.2/"
WP_ORG_VULN_API = "https://wordpress.org/plugins/vulnerabilities/v1/"
WP_ORG_VULN_API_FALLBACK = "https://wpscan.com/api/v3/plugins"


def gh_api(endpoint: str, method: str = "GET", data: dict = None) -> dict:
    """Call GitHub API via gh CLI to avoid auth-header injection scanner issues."""
    cmd = ["gh", "api", endpoint, "--method", method]
    if data:
        cmd.extend(["-f", json.dumps(data)])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"gh api failed: {result.stderr}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def gh_api_json(endpoint: str, json_data: str = None, method: str = "GET") -> dict:
    """Call GitHub API via gh CLI with JSON body."""
    cmd = ["gh", "api", endpoint, "--method", method]
    if json_data:
        # Write JSON to temp file and use --input flag
        import tempfile
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
    """Load processed CVE tracking state."""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"processed_cves": [], "last_check": None, "last_comment_id": None}


def save_state(state: dict):
    """Save state to disk."""
    state["last_check"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def http_get(url: str, headers: dict = None, timeout: int = 30) -> Optional[str]:
    """Simple HTTP GET with error handling."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[WARN] HTTP GET {url}: {e}")
        return None


def http_get_json(url: str, headers: dict = None, timeout: int = 30) -> Optional[dict]:
    """HTTP GET returning parsed JSON."""
    text = http_get(url, headers, timeout)
    if text:
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            print(f"[WARN] JSON parse error {url}: {e}")
    return None


# ─────────────────────────────────────────────
# CVE SOURCE 1: WordPress.org Recent Security Updates
# ─────────────────────────────────────────────
def fetch_wporg_recent_updates() -> list:
    """Fetch recently updated plugins from WordPress.org to find security fixes."""
    vulns = []
    try:
        # Get recently updated plugins with security tag
        data = http_get_json(
            f"{WP_ORG_API}?action=query_plugins&tag=security&per_page=20&orderby=updated",
            headers={"User-Agent": "CodeVigilant-CVE-Monitor/1.0"}
        )
        if data and "plugins" in data:
            for plugin in data["plugins"]:
                slug = plugin.get("slug", "")
                name = plugin.get("name", "")
                last_updated = plugin.get("last_updated", "")
                # Check if the plugin was updated in the last 7 days
                if last_updated:
                    try:
                        update_date = datetime.strptime(last_updated, "%Y-%m-%d %I:%M%p %Z")
                        days_since = (datetime.now(timezone.utc) - update_date.replace(tzinfo=timezone.utc)).days
                        if days_since <= 7:
                            # This is a recently updated plugin - check its changelog
                            # for security-related mentions
                            changelog_url = f"https://wordpress.org/plugins/{slug}/#developers"
                            vulns.append({
                                "cve_id": f"WPORG-{slug.upper()}-{datetime.now(timezone.utc).strftime('%Y%m%d')}",
                                "source": "wordpress.org",
                                "plugin_slug": slug,
                                "title": f"Recent update to {name}",
                                "vuln_type": "unknown",
                                "description": f"Plugin {name} was updated on {last_updated}. Check changelog for security fixes.",
                                "affected_versions": [],
                                "patched_versions": [],
                                "url": f"https://wordpress.org/plugins/{slug}/",
                                "needs_changelog_check": True,
                            })
                    except (ValueError, TypeError):
                        pass
        print(f"[INFO] WordPress.org recent updates: {len(vulns)} plugins checked")
    except Exception as e:
        print(f"[ERROR] WordPress.org API: {e}")
    return vulns


# ─────────────────────────────────────────────
# CVE SOURCE 2: NVD/CVE RSS Feed (WordPress-tagged)
# ─────────────────────────────────────────────
def fetch_nvd_wordpress_cves() -> list:
    """Search NVD for recent WordPress-related CVEs."""
    vulns = []
    # Search for recent WordPress CVEs via NVD API 2.0
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=7)
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch=wordpress+plugin"
        f"&keywordExactMatch"
        f"&pubStartDate={start_date.strftime('%Y-%m-%dT00:00:00.000')}"
        f"&pubEndDate={end_date.strftime('%Y-%m-%dT23:59:59.999')}"
        f"&resultsPerPage=20"
    )
    data = http_get_json(url, timeout=60)
    if data and "vulnerabilities" in data:
        for v in data["vulnerabilities"]:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # Extract plugin name from description
            plugin_slug = extract_plugin_from_cve_desc(desc)

            if plugin_slug:
                # Classify vulnerability type from CWE
                vuln_type = classify_cve_type(cve)
                vulns.append({
                    "cve_id": cve_id,
                    "source": "nvd",
                    "plugin_slug": plugin_slug,
                    "title": desc[:200],
                    "vuln_type": vuln_type,
                    "description": desc,
                    "affected_versions": [],
                    "patched_versions": [],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
    print(f"[INFO] NVD API: {len(vulns)} WordPress CVEs found")
    return vulns


def extract_plugin_from_cve_desc(desc: str) -> Optional[str]:
    """Try to extract a WordPress plugin slug from CVE description."""
    # Common patterns in CVE descriptions - be more specific
    patterns = [
        # "WordPress plugin X before version" is the most common NVD pattern
        r'WordPress\s+plugin\s+["\']?([a-zA-Z0-9_-]+)["\']?\s+(?:before|through|up to|prior)',
        # "X WordPress plugin before"
        r'["\']?([a-zA-Z0-9_-]+)["\']?\s+WordPress\s+plugin\s+(?:before|through|up to)',
        # "plugin X" with version context
        r'plugin\s+["\']?([a-zA-Z0-9_-]+)["\']?\s+(?:before|through|up to|prior)',
        # "X Plugin before" (proper noun + Plugin)
        r'([A-Z][a-zA-Z0-9_-]+)\s+Plugin\s+(?:before|through|up to)',
        # "in X before" (common NVD phrasing)
        r'in\s+["\']?([a-zA-Z0-9_-]+)["\']?\s+(?:before|through|up to|prior)',
        # "affects X before"
        r'affects?\s+["\']?([a-zA-Z0-9_-]+)["\']?\s+(?:before|through|up to)',
        # Generic: quoted slug
        r'["\']([a-zA-Z0-9_-]+)["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, desc, re.IGNORECASE)
        if match:
            slug = match.group(1).lower().strip()
            # Filter out common false positives
            false_positives = {
                'before', 'through', 'to', 'the', 'and', 'or', 'in', 'on',
                'for', 'with', 'from', 'that', 'this', 'has', 'was', 'are',
                'not', 'may', 'can', 'could', 'would', 'should', 'will',
                'wordpress', 'plugin', 'theme', 'vulnerability', 'vulnerabilities',
                'allowing', 'allow', 'remote', 'local', 'file', 'code', 'attack',
            }
            if slug not in false_positives and len(slug) > 2:
                return slug
    return None


def classify_cve_type(cve: dict) -> str:
    """Classify vulnerability type from CVE data."""
    weaknesses = cve.get("configurations", [])
    desc_text = " ".join(
        d.get("value", "")
        for d in cve.get("descriptions", [])
        if d.get("lang") == "en"
    ).lower()

    type_keywords = {
        "sql injection": ["sql injection", "sqli", "blind sql"],
        "xss": ["cross-site scripting", "xss", "reflected xss", "stored xss"],
        "rce": ["remote code execution", "rce", "command injection", "code injection"],
        "ssrf": ["server-side request forgery", "ssrf"],
        "lfi": ["local file inclusion", "path traversal", "directory traversal"],
        "rfi": ["remote file inclusion"],
        "deserialization": ["deserialization", "insecure deserialization", "unserialize"],
        "csrf": ["cross-site request forgery", "csrf"],
        "privilege_escalation": ["privilege escalation", "authentication bypass", "privilege"],
        "directory_traversal": ["directory traversal", "path traversal"],
    }

    for vuln_type, keywords in type_keywords.items():
        for kw in keywords:
            if kw in desc_text:
                return vuln_type

    return "unknown"


# ─────────────────────────────────────────────
# CVE SOURCE 3: Wordfence / WPScan blogs (scraped)
# ─────────────────────────────────────────────
def fetch_recent_exploit_news() -> list:
    """Search for recent WordPress security news via web search."""
    vulns = []
    # Use WPScan vulnerability database API (public, no auth needed for basic)
    url = "https://wpscan.com/plugins"
    # Since we can't easily scrape, use the WordPress.org vulnerability data
    # and the NVD feed as primary sources. This is a placeholder for future
    # blog RSS integration.
    return vulns


# ─────────────────────────────────────────────
# PLUGIN SOURCE CODE DOWNLOAD
# ─────────────────────────────────────────────
def download_plugin(slug: str) -> Optional[Path]:
    """Download and extract a WordPress plugin from wordpress.org."""
    plugin_dir = SCAN_CACHE / slug
    if plugin_dir.exists():
        # Already downloaded, use cached
        return plugin_dir

    zip_path = SCAN_CACHE / f"{slug}.zip"
    url = f"https://downloads.wordpress.org/plugin/{slug}.latest-stable.zip"

    print(f"[INFO] Downloading plugin: {slug}")
    try:
        result = subprocess.run(
            ["curl", "-sL", "-o", str(zip_path), "-w", "%{http_code}", url],
            capture_output=True, text=True, timeout=60
        )
        # Check HTTP status from curl
        http_code = result.stdout.strip()
        if http_code != "200" or not zip_path.exists():
            if zip_path.exists():
                zip_path.unlink()
            print(f"[WARN] Download failed for {slug} (HTTP {http_code})")
            return None

        # Check if it's actually a zip (minimum size)
        if zip_path.stat().st_size < 100:
            zip_path.unlink()
            print(f"[WARN] Empty/invalid zip for {slug}")
            return None

        # Extract
        extract_dir = SCAN_CACHE / slug
        extract_dir.mkdir(exist_ok=True)
        result = subprocess.run(
            ["unzip", "-o", "-q", str(zip_path), "-d", str(extract_dir)],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"[WARN] Extract failed for {slug}: {result.stderr[:200]}")
            return None

        # The plugin files might be in a subdirectory like slug/slug/
        # Find the actual PHP files
        php_files = list(extract_dir.rglob("*.php"))
        if not php_files:
            # Check one level deeper
            subdirs = [d for d in extract_dir.iterdir() if d.is_dir()]
            if subdirs:
                return subdirs[0]
            return None

        return extract_dir
    except subprocess.TimeoutExpired:
        print(f"[WARN] Download timeout for {slug}")
        if zip_path.exists():
            zip_path.unlink()
        return None
    except Exception as e:
        print(f"[WARN] Download error for {slug}: {e}")
        if zip_path.exists():
            zip_path.unlink()
        return None


def cleanup_plugin(slug: str):
    """Remove downloaded plugin files."""
    plugin_dir = SCAN_CACHE / slug
    zip_path = SCAN_CACHE / f"{slug}.zip"
    if plugin_dir.exists():
        subprocess.run(["rm", "-rf", str(plugin_dir)])
    if zip_path.exists():
        zip_path.unlink()


# ─────────────────────────────────────────────
# SEMGREP SCANNING
# ─────────────────────────────────────────────
def run_semgrep(plugin_dir: Path) -> dict:
    """Run all semgrep rules against a plugin directory. Returns findings."""
    result = {
        "findings": [],
        "rules_triggered": [],
        "rules_not_triggered": [],
        "all_rules": [],
        "total_findings": 0,
    }

    try:
        # Validate rules first
        validate = subprocess.run(
            [SEMPEG_BIN, "--validate", "--config", str(RULES_DIR)],
            capture_output=True, text=True, timeout=120
        )

        # Run semgrep with JSON output - 60s timeout per plugin
        scan = subprocess.run(
            [SEMPEG_BIN, "--config", str(RULES_DIR),
             "--json", "--timeout", "30",
             "--max-target-bytes", "10485760",  # 10MB
             "--jobs", "2",  # Limit parallelism
             str(plugin_dir)],
            capture_output=True, text=True, timeout=120  # 2 min total timeout
        )

        if scan.stdout.strip():
            try:
                output = json.loads(scan.stdout)
                findings = output.get("results", [])
                result["findings"] = findings
                result["total_findings"] = len(findings)

                # Track which rules triggered
                triggered_rules = set()
                for f in findings:
                    rule_id = f.get("check_id", "unknown")
                    triggered_rules.add(rule_id)
                    result["rules_triggered"].append({
                        "rule_id": rule_id,
                        "file": f.get("path", ""),
                        "line": f.get("start", {}).get("line", 0),
                        "message": f.get("extra", {}).get("message", ""),
                        "severity": f.get("extra", {}).get("severity", ""),
                    })

                result["rules_triggered"] = list(triggered_rules)
            except json.JSONDecodeError as e:
                print(f"[ERROR] Semgrep JSON parse: {e}")
    except subprocess.TimeoutExpired:
        print(f"[WARN] Semgrep scan timed out for {plugin_dir}")
    except Exception as e:
        print(f"[ERROR] Semgrep scan failed: {e}")

    # Also list all rules to compare
    try:
        list_rules = subprocess.run(
            [SEMPEG_BIN, "--config", str(RULES_DIR), "--validate"],
            capture_output=True, text=True, timeout=60
        )
        # Parse rule list from YAML files
        all_rules = set()
        for yaml_file in RULES_DIR.rglob("*.yaml"):
            with open(yaml_file) as f:
                content = f.read()
                # Extract rule IDs
                ids = re.findall(r'-\s*id:\s*(.+)', content)
                for rule_id in ids:
                    all_rules.add(rule_id.strip())
        result["all_rules"] = list(all_rules)
        result["rules_not_triggered"] = [
            r for r in result["all_rules"]
            if r not in result["rules_triggered"]
        ]
    except Exception as e:
        print(f"[WARN] Could not list rules: {e}")

    return result


# ─────────────────────────────────────────────
# VULNERABILITY ANALYSIS
# ─────────────────────────────────────────────
def analyze_vulnerability(vuln: dict, scan_results: dict) -> dict:
    """Analyze if a vulnerability would have been caught by existing rules."""
    vuln_type = vuln.get("vuln_type", "unknown")
    description = vuln.get("description", "").lower()
    title = vuln.get("title", "").lower()
    combined = f"{title} {description}"

    # Map vulnerability types to relevant rule categories
    rule_mappings = {
        "sql injection": {
            "patterns": ["getpost", "cookie", "server", "user_agent", "sqli", "prepared-sql"],
            "keywords": ["sql", "query", "prepare", "db->query", "db->prepare", "wpdb"],
        },
        "xss": {
            "patterns": ["basic_xss", "output-escaping", "variables_substitutes"],
            "keywords": ["echo", "print", "html", "script", "esc_html", "esc_attr"],
        },
        "rce": {
            "patterns": ["rce", "dangerous-functions", "restricted-functions"],
            "keywords": ["eval", "exec", "system", "passthru", "shell_exec", "file_get_contents"],
        },
        "ssrf": {
            "patterns": ["ssrf", "restricted-functions"],
            "keywords": ["file_get_contents", "curl", "wp_remote", "fopen"],
        },
        "lfi": {
            "patterns": ["dynamic-include", "restricted-functions"],
            "keywords": ["include", "require", "file_get_contents", "file_put_contents"],
        },
        "rfi": {
            "patterns": ["dynamic-include", "restricted-functions"],
            "keywords": ["include", "require", "url", "http"],
        },
        "csrf": {
            "patterns": ["nonce-verification"],
            "keywords": ["nonce", "verify", "wp_nonce"],
        },
        "deserialization": {
            "patterns": ["deserialize", "restricted-functions"],
            "keywords": ["unserialize", "serialize"],
        },
        "privilege_escalation": {
            "patterns": ["capabilities", "global-override"],
            "keywords": ["admin", "capability", "role", "privilege"],
        },
    }

    mapping = rule_mappings.get(vuln_type, {})
    relevant_patterns = mapping.get("patterns", [])
    relevant_keywords = mapping.get("keywords", [])

    # Check if any rules matched
    rules_triggered = scan_results.get("rules_triggered", [])
    all_rules = scan_results.get("all_rules", [])

    # Determine detection
    caught = False
    catching_rules = []

    for rule in rules_triggered:
        rule_lower = rule.lower()
        for pattern in relevant_patterns:
            if pattern in rule_lower:
                caught = True
                catching_rules.append(rule)

    # If no specific match, check if general security rules triggered
    if not caught and rules_triggered:
        # Any rule triggered = partial detection
        for rule in rules_triggered:
            if any(kw in rule.lower() for kw in relevant_keywords):
                caught = True
                catching_rules.append(rule)

    return {
        "caught": caught,
        "catching_rules": catching_rules,
        "relevant_patterns": relevant_patterns,
        "scan_summary": {
            "total_findings": scan_results.get("total_findings", 0),
            "rules_triggered_count": len(scan_results.get("rules_triggered", [])),
            "rules_not_triggered_count": len(scan_results.get("rules_not_triggered", [])),
        },
    }


# ─────────────────────────────────────────────
# RULE GENERATION FOR MISSED DETECTIONS
# ─────────────────────────────────────────────
def generate_semgrep_rule(vuln: dict, plugin_dir: Path) -> Optional[Path]:
    """Generate a semgrep rule for a missed vulnerability."""
    vuln_type = vuln.get("vuln_type", "unknown")
    plugin_slug = vuln.get("plugin_slug", "unknown")
    cve_id = vuln.get("cve_id", "unknown")
    description = vuln.get("description", "")

    # Map vuln types to rule structures
    rule_templates = {
        "sql injection": {
            "id": f"codevigilant.php.wordpress.sqli.cve.{cve_id.replace('-', '_').lower()}",
            "pattern": "- pattern: $DB->query(...)\n  pattern-not-inside: $DB->prepare(...)",
            "message": f"SQL injection in {plugin_slug} ({cve_id}): query without prepared statement",
            "severity": "ERROR",
            "metadata": {"cwe": "CWE-89", "owasp": "A03:2021"},
        },
        "xss": {
            "id": f"codevigilant.php.wordpress.xss.cve.{cve_id.replace('-', '_').lower()}",
            "pattern": "- pattern-regex: echo[\\s\\S]*?\\$_GET|echo[\\s\\S]*?\\$_POST|echo[\\s\\S]*?\\$_REQUEST",
            "message": f"Potential XSS in {plugin_slug} ({cve_id}): unescaped user input in echo",
            "severity": "WARNING",
            "metadata": {"cwe": "CWE-79", "owasp": "A03:2021"},
        },
        "rce": {
            "id": f"codevigilant.php.wordpress.rce.cve.{cve_id.replace('-', '_').lower()}",
            "pattern": "- pattern-either:\n    - pattern: eval(...)\n    - pattern: system(...)\n    - pattern: exec(...)\n    - pattern: shell_exec(...)",
            "message": f"RCE in {plugin_slug} ({cve_id}): dangerous function execution",
            "severity": "CRITICAL",
            "metadata": {"cwe": "CWE-78", "owasp": "A03:2021"},
        },
        "ssrf": {
            "id": f"codevigilant.php.wordpress.ssrf.cve.{cve_id.replace('-', '_').lower()}",
            "pattern": "- pattern-either:\n    - pattern: file_get_contents($_GET[...])\n    - pattern: file_get_contents($_POST[...])\n    - pattern: file_get_contents($_REQUEST[...])",
            "message": f"SSRF in {plugin_slug} ({cve_id}): file_get_contents with user input",
            "severity": "ERROR",
            "metadata": {"cwe": "CWE-918", "owasp": "A10:2021"},
        },
        "lfi": {
            "id": f"codevigilant.php.wordpress.lfi.cve.{cve_id.replace('-', '_').lower()}",
            "pattern": "- pattern-either:\n    - pattern: include(...)\n    - pattern: require(...)",
            "message": f"LFI in {plugin_slug} ({cve_id}): potential local file inclusion",
            "severity": "ERROR",
            "metadata": {"cwe": "CWE-98", "owasp": "A03:2021"},
        },
    }

    template = rule_templates.get(vuln_type)
    if not template:
        # Generic template for unknown types
        template = {
            "id": f"codevigilant.php.wordpress.{vuln_type}.cve.{cve_id.replace('-', '_').lower()}",
            "pattern": "- pattern-either:\n    - pattern: eval(...)\n    - pattern: system(...)\n    - pattern: exec(...)\n    - pattern: shell_exec(...)\n    - pattern: passthru(...)\n    - pattern: popen(...)",
            "message": f"Potential vulnerability in {plugin_slug} ({cve_id}): {vuln_type}",
            "severity": "WARNING",
            "metadata": {"cwe": "CWE-0", "owasp": "A03:2021"},
        }

    # Create the rule file - quote message to avoid YAML colon issues
    message = template['message'].replace('"', '\\"')
    rule_content = f"""rules:
  - id: {template['id']}
    patterns:
      - pattern: {template['pattern'].split('pattern: ')[1] if 'pattern: ' in template['pattern'] else template['pattern']}
    message: "{message}"
    languages: [php]
    severity: {template['severity']}
    metadata:
      cwe: "{template['metadata']['cwe']}"
      owasp: "{template['metadata']['owasp']}"
      technology: [wordpress]
      confidence: LOW
      source: nvd-cve-analysis
      cve: "{cve_id}"
      plugin: "{plugin_slug}"
      references:
        - "{vuln.get('url', '')}"
      license: MIT
"""

    # Determine rule subdirectory
    type_dirs = {
        "sql injection": "wordpress/SQLi",
        "xss": "wordpress/xss",
        "rce": "wordpress/rce",
        "ssrf": "wordpress/ssrf",
        "lfi": "wordpress/lfi",
        "rfi": "wordpress/rfi",
        "deserialization": "wordpress/deserialisation",
        "csrf": "coding-standards/security",
        "privilege_escalation": "coding-standards/wordpress-security",
    }

    subdir = type_dirs.get(vuln_type, f"wordpress/{vuln_type}")
    rule_dir = RULES_DIR / subdir
    rule_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rule_dir / f"{cve_id.lower().replace('-', '_')}.yaml"

    with open(rule_file, "w") as f:
        f.write(rule_content)

    print(f"[INFO] Generated rule: {rule_file}")
    return rule_file


# ─────────────────────────────────────────────
# PR CREATION FOR MISSED DETECTIONS
# ─────────────────────────────────────────────
def create_rule_pr(vulns: list, rule_files: list) -> Optional[int]:
    """Create a PR with new semgrep rules for missed detections."""
    if not rule_files:
        return None

    # Ensure we're on main and up to date
    subprocess.run(
        ["git", "fetch", "upstream", "main"],
        capture_output=True, cwd=REPO_DIR
    )
    subprocess.run(
        ["git", "checkout", "main"],
        capture_output=True, cwd=REPO_DIR
    )
    subprocess.run(
        ["git", "merge", "upstream/main"],
        capture_output=True, cwd=REPO_DIR
    )

    # Create branch
    branch_name = f"feat/cve-rules-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    subprocess.run(
        ["git", "checkout", "-b", branch_name],
        capture_output=True, cwd=REPO_DIR
    )

    # Stage new rules
    for rule_file in rule_files:
        subprocess.run(
            ["git", "add", str(rule_file.relative_to(REPO_DIR))],
            capture_output=True, cwd=REPO_DIR
        )

    # Validate all rules
    validate = subprocess.run(
        [SEMPEG_BIN, "--validate", "--config", str(RULES_DIR)],
        capture_output=True, text=True, timeout=120, cwd=REPO_DIR
    )
    if validate.returncode != 0:
        print(f"[WARN] Rule validation warnings: {validate.stderr[:500]}")

    # Commit
    cve_list = ", ".join(v.get("cve_id", "unknown") for v in vulns[:5])
    if len(vulns) > 5:
        cve_list += f" +{len(vulns) - 5} more"

    subprocess.run(
        ["git", "commit", "-S", "-m",
         f"feat: add semgrep rules for {cve_list}\n\n"
         f"New rules to detect vulnerabilities reported in:\n" +
         "\n".join(f"- {v.get('cve_id', 'N/A')}: {v.get('title', '')[:100]}"
                    for v in vulns)],
        capture_output=True, cwd=REPO_DIR
    )

    # Push
    push = subprocess.run(
        ["git", "push", "-u", "origin", branch_name],
        capture_output=True, text=True, cwd=REPO_DIR
    )
    if push.returncode != 0:
        print(f"[ERROR] Push failed: {push.stderr}")
        subprocess.run(["git", "checkout", "main"], cwd=REPO_DIR)
        subprocess.run(["git", "branch", "-D", branch_name], cwd=REPO_DIR)
        return None

    # Create PR
    pr_body = f"""## Summary

New semgrep rules added to detect the following WordPress plugin/theme vulnerabilities:

| CVE | Plugin | Type | Status |
|-----|--------|------|--------|
"""
    for v in vulns:
        pr_body += f"| {v.get('cve_id', 'N/A')} | {v.get('plugin_slug', 'N/A')} | {v.get('vuln_type', 'N/A')} | New Rule |\n"

    pr_body += f"""
## Vulnerability Details

"""
    for v in vulns:
        pr_body += f"""### {v.get('cve_id', 'N/A')} - {v.get('plugin_slug', 'N/A')}
- **Type**: {v.get('vuln_type', 'unknown')}
- **Description**: {v.get('description', '')[:300]}
- **Source**: {v.get('url', 'N/A')}

"""

    pr_body += """## Verification

- [ ] Rules validated with `semgrep --validate`
- [ ] Each rule tested against sample vulnerable code
- [ ] Metadata follows repo conventions

---

*Auto-generated by WordPress CVE Monitor*"""

    pr = gh_api_json(
        "repos/ai-anant/codevigilant_semgrep_rules/pulls",
        json.dumps({
            "title": f"🛡️ CVE Rules: {cve_list}",
            "body": pr_body,
            "head": branch_name,
            "base": "main",
        }),
        method="POST"
    )

    pr_number = pr.get("number")
    if pr_number:
        print(f"[INFO] Created PR #{pr_number}: {pr.get('html_url', '')}")

        # Also add comment to upstream repo if possible
        try:
            gh_api_json(
                "repos/CodeVigilant/codevigilant_semgrep_rules/pulls",
                json.dumps({
                    "title": f"🛡️ CVE Rules: {cve_list}",
                    "body": pr_body,
                    "head": f"ai-anant:{branch_name}",
                    "base": "main",
                }),
                method="POST"
            )
        except Exception:
            pass  # PR creation on upstream may fail

    # Cleanup
    subprocess.run(["git", "checkout", "main"], cwd=REPO_DIR)
    subprocess.run(["git", "branch", "-D", branch_name], cwd=REPO_DIR)

    return pr_number


# ─────────────────────────────────────────────
# TRACKING ISSUE COMMENT
# ─────────────────────────────────────────────
def update_tracking_issue(vulns: list, analyses: list, pr_number: Optional[int]):
    """Add a comment to the tracking issue with CVE analysis results."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    body = f"## 📊 CVE Scan Results — {timestamp}\n\n"
    body += f"**Scan Date**: {timestamp}\n"
    body += f"**CVEs Analyzed**: {len(vulns)}\n"
    if pr_number:
        body += f"**PR Created**: #{pr_number}\n"
    body += "\n"

    # Caught vulnerabilities
    caught = [a for a in analyses if a.get("caught")]
    missed = [a for a in analyses if not a.get("caught")]

    if caught:
        body += "### ✅ Detected by Existing Rules\n\n"
        for a in caught:
            vuln = a["vuln"]
            body += f"- **{vuln.get('cve_id', 'N/A')}** — {vuln.get('plugin_slug', 'N/A')} ({vuln.get('vuln_type', 'unknown')})\n"
            body += f"  - Caught by: `{', '.join(a.get('catching_rules', []))}`\n"
            body += f"  - Source: {vuln.get('url', 'N/A')}\n\n"

    if missed:
        body += "### ❌ Not Detected — New Rules Needed\n\n"
        for a in missed:
            vuln = a["vuln"]
            body += f"- **{vuln.get('cve_id', 'N/A')}** — {vuln.get('plugin_slug', 'N/A')} ({vuln.get('vuln_type', 'unknown')})\n"
            body += f"  - {vuln.get('description', '')[:200]}\n"
            body += f"  - Source: {vuln.get('url', 'N/A')}\n\n"

    body += "---\n*Auto-generated by WordPress CVE Monitor*\n"

    # Post comment to tracking issue
    comment = gh_api_json(
        "repos/ai-anant/codevigilant_semgrep_rules/issues/1/comments",
        json.dumps({"body": body}),
        method="POST"
    )
    if comment:
        print(f"[INFO] Added comment to issue #{TRACKING_ISSUE}")


# ─────────────────────────────────────────────
# MAIN WORKFLOW
# ─────────────────────────────────────────────
def main():
    print(f"[INFO] WordPress CVE Monitor starting at {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    state = load_state()
    processed = set(state.get("processed_cves", []))

    # 1. Fetch CVEs from all sources
    all_vulns = []
    all_vulns.extend(fetch_wporg_recent_updates())
    all_vulns.extend(fetch_nvd_wordpress_cves())
    all_vulns.extend(fetch_recent_exploit_news())

    # Deduplicate and filter already processed
    seen = set()
    new_vulns = []
    for v in all_vulns:
        cve_id = v.get("cve_id", "")
        if cve_id and cve_id not in processed and cve_id not in seen:
            seen.add(cve_id)
            new_vulns.append(v)

    # Limit to top 10 most recent CVEs per run to avoid timeout
    new_vulns = new_vulns[:10]
    if not new_vulns:
        print("[INFO] No new CVEs found since last check.")
        save_state(state)
        return

    print(f"[INFO] Found {len(new_vulns)} new CVEs to analyze")

    # 2. Analyze each CVE
    analyses = []
    missed_vulns = []
    missed_rules = []

    for vuln in new_vulns:
        cve_id = vuln.get("cve_id", "unknown")
        plugin_slug = vuln.get("plugin_slug", "")
        print(f"\n[INFO] Analyzing {cve_id} ({plugin_slug})...")

        # Download plugin
        plugin_dir = None
        if plugin_slug:
            plugin_dir = download_plugin(plugin_slug)

        # Run semgrep
        if plugin_dir:
            scan_results = run_semgrep(plugin_dir)
            analysis = analyze_vulnerability(vuln, scan_results)
            analysis["vuln"] = vuln
            analyses.append(analysis)

            if not analysis["caught"]:
                missed_vulns.append(vuln)
                # Generate new rule
                rule_file = generate_semgrep_rule(vuln, plugin_dir)
                if rule_file:
                    missed_rules.append((vuln, rule_file))

            # Cleanup
            cleanup_plugin(plugin_slug)
        else:
            # Can't download, still mark for rule generation
            print(f"[WARN] Could not download {plugin_slug}, generating rule from description")
            missed_vulns.append(vuln)
            analysis = {"caught": False, "catching_rules": [], "vuln": vuln}
            analyses.append(analysis)

        # Mark as processed
        processed.add(cve_id)

    # 3. Create PR for missed detections
    pr_number = None
    if missed_rules:
        vulns_for_pr = [v for v, _ in missed_rules]
        rule_files = [r for _, r in missed_rules]
        pr_number = create_rule_pr(vulns_for_pr, rule_files)

    # 4. Update tracking issue
    update_tracking_issue(new_vulns, analyses, pr_number)

    # 5. Save state
    state["processed_cves"] = list(processed)
    save_state(state)

    # Summary
    caught_count = sum(1 for a in analyses if a["caught"])
    missed_count = len(analyses) - caught_count
    print(f"\n[DONE] Analysis complete:")
    print(f"  - CVEs analyzed: {len(new_vulns)}")
    print(f"  - Caught by existing rules: {caught_count}")
    print(f"  - Missed (new rules needed): {missed_count}")
    print(f"  - PR created: {'#' + str(pr_number) if pr_number else 'N/A'}")


if __name__ == "__main__":
    main()
