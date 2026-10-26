#!/usr/bin/env python3

import argparse
import datetime
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

NGINX_CONF = Path("/etc/nginx/nginx.conf")
NGINX_SITE = Path("/etc/nginx/sites-available/default")
SNORT_CONF = Path("/etc/snort/snort.conf")
SNORT_RULES = Path("/etc/snort/rules/local.rules")


def run(command):
    """Run a command and stop if it fails."""
    print(f"\n$ {' '.join(map(str, command))}")
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    if result.stdout:
        print(result.stdout, end="")

    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(map(str, command))}")

    return result


def backup(path):
    """Create a timestamped backup before modifying a file."""
    if path.exists():
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = path.with_name(
            f"{path.name}.backup_{timestamp}"
        )
        shutil.copy2(path, backup_path)
        print(f"Backup created: {backup_path}")


def configure_nginx_version():
    text = NGINX_CONF.read_text(encoding="utf-8")

    if not re.search(r"(?m)^\s*http\s*\{", text):
        raise RuntimeError("Could not find the http block in nginx.conf.")

    if re.search(r"(?m)^\s*server_tokens\s+off\s*;", text):
        print("Nginx version hiding is already configured.")
        return

    match = re.search(r"(?m)^\s*http\s*\{", text)
    updated = (
        text[:match.end()]
        + "\n    server_tokens off;\n"
        + text[match.end():]
    )

    backup(NGINX_CONF)
    NGINX_CONF.write_text(updated, encoding="utf-8")
    print("Configured server_tokens off.")


def configure_nginx_headers(node_tag):
    if not NGINX_SITE.exists():
        raise FileNotFoundError(
            f"Site configuration not found: {NGINX_SITE}"
        )

    text = NGINX_SITE.read_text(encoding="utf-8")

    directives = [
        'add_header X-Frame-Options "DENY" always;',
        'add_header X-Content-Type-Options "nosniff" always;',
        f'add_header X-Vukani-Node "{node_tag}" always;',
    ]

    missing = [directive for directive in directives if directive not in text]

    if not missing:
        print("Required Nginx headers are already configured.")
        return

    match = re.search(r"(?m)^\s*server\s*\{", text)
    if not match:
        raise RuntimeError("Could not find a server block in the site config.")

    insertion = "\n    " + "\n    ".join(missing) + "\n"
    updated = text[:match.end()] + insertion + text[match.end():]

    backup(NGINX_SITE)
    NGINX_SITE.write_text(updated, encoding="utf-8")
    print("Added required security headers.")


def configure_snort_rule(node_tag, sid, tracking_path):
    if not SNORT_CONF.exists():
        raise FileNotFoundError(f"Missing Snort config: {SNORT_CONF}")

    if not SNORT_RULES.exists():
        raise FileNotFoundError(f"Missing local rules: {SNORT_RULES}")

    config = SNORT_CONF.read_text(encoding="utf-8")

    include_patterns = [
        r'(?m)^\s*include\s+\$RULE_PATH/local\.rules\s*$',
        r'(?m)^\s*include\s+["\']?/etc/snort/rules/local\.rules["\']?\s*;?\s*$',
    ]

    if not any(re.search(pattern, config) for pattern in include_patterns):
        raise RuntimeError(
            "snort.conf does not appear to include local.rules. "
            "Configure the appropriate include for your Snort version."
        )

    text = SNORT_RULES.read_text(encoding="utf-8")

    if re.search(rf"\bsid\s*:\s*{sid}\s*;", text):
        existing_rule = (
            f'sid:{sid};' in text
            and f'"{node_tag} SQL injection attempt against tracking page"' in text
        )
        if existing_rule:
            print("The requested Snort rule already exists.")
            return

        raise RuntimeError(
            f"SID {sid} is already used in local.rules. "
            "Choose an assigned, unused SID."
        )

    escaped_path = tracking_path.replace("\\", "\\\\").replace('"', '\\"')

    rule = (
        "alert tcp any any -> $HOME_NET $HTTP_PORTS "
        f'(msg:"{node_tag} SQL injection attempt against tracking page"; '
        'flow:to_server,established; '
        f'content:"{escaped_path}"; http_uri; '
        'content:"\'"; http_uri; '
        f"sid:{sid}; rev:1;)"
    )

    backup(SNORT_RULES)

    separator = "" if not text or text.endswith("\n") else "\n"
    SNORT_RULES.write_text(
        text + separator + rule + "\n",
        encoding="utf-8",
    )

    print("Added Snort local rule:")
    print(rule)


def main():
    parser = argparse.ArgumentParser(
        description="Configure Nginx and Snort for p21-web."
    )
    parser.add_argument("--node-tag", required=True)
    parser.add_argument("--sid", required=True, type=int)
    parser.add_argument(
        "--tracking-path",
        default="/tracking",
        help="Tracking endpoint path (default: /tracking).",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Please run this script with sudo.", file=sys.stderr)
        return 1

    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.node_tag):
        print("Invalid node tag.", file=sys.stderr)
        return 1

    if not 1 <= args.sid <= 4294967295:
        print("SID must be a valid positive 32-bit integer.", file=sys.stderr)
        return 1

    if not args.tracking_path.startswith("/") or '"' in args.tracking_path:
        print("Tracking path must start with / and must not contain quotes.")
        return 1

    try:
        print("=== Configure Nginx ===")
        configure_nginx_version()
        configure_nginx_headers(args.node_tag)

        print("\n=== Test Nginx configuration ===")
        run(["nginx", "-t"])

        print("\n=== Start and reload Nginx ===")
        run(["systemctl", "enable", "--now", "nginx"])
        run(["systemctl", "reload", "nginx"])
        run(["systemctl", "is-active", "nginx"])

        print("\n=== Configure Snort ===")
        configure_snort_rule(
            args.node_tag,
            args.sid,
            args.tracking_path,
        )

        print("\n=== Test Snort configuration ===")
        run(["snort", "-T", "-c", str(SNORT_CONF)])

        print("\nConfiguration and validation completed.")
        print("No zaio commands were executed.")
        print("\nWhen you are ready, run these commands manually:")
        print("  sudo zaio check p21-web")
        print("  sudo zaio end p21-web")

        return 0

    except (RuntimeError, FileNotFoundError, PermissionError) as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        print("Review the configuration and backups before retrying.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
