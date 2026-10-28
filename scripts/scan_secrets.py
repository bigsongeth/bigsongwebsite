#!/usr/bin/env python3
"""Report secret locations without printing secret values."""
import argparse
import json
import re
import subprocess
from pathlib import Path

ENV_FILE = re.compile(r"(^|/)\.env(?:\..+)?$")
URL_PASSWORD = re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/]+:[^\s@]+@", re.I)
LITERAL = re.compile(r"""(?ix)(?:NEXTAUTH_SECRET|JWT_SECRET|OSS_ACCESS_(?:KEY|SECRET)|ADMIN_PASSWORD_HASH|accessKeySecret)\s*[:=]\s*["']([^"']{6,})["']""")

SECRET_ASSIGNMENT = re.compile(r"""^\s*(?:-\s*)?(?:export\s+)?["']?(NEXTAUTH_SECRET|JWT_SECRET|SECRET_KEY|SESSION_SECRET|OSS_ACCESS_KEY|OSS_ACCESS_SECRET|ADMIN_PASSWORD_HASH|ADMIN_PASSWORD|POSTGRES_PASSWORD|SITE_PASSWORD|INGEST_TOKEN|API_KEY|accessKeySecret|accessKeyId)["']?\s*[:=]\s*(.*?)\s*[,;]?\s*$""", re.I)

def is_empty_or_runtime_reference(value):
    value = value.strip().rstrip(",;").strip()
    if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
        value = value[1:-1].strip()
    if not value or value.startswith("#") or value.lower() in ("null", "none"):
        return True
    if re.fullmatch(r"\$\{[A-Za-z_]\w*(?::\?[^}]+|\?[^}]+)?\}", value):
        return True
    if re.fullmatch(r"""(?:process\.env\.[A-Za-z_]\w*|os\.environ\[['"][A-Za-z_]\w*['"]\])!?""", value):
        return True
    return False

def scan(path, text):
    findings = []
    if ENV_FILE.search(path) and Path(path).name != ".env.example":
        findings.append({"path": path, "line": 1, "rule": "tracked-runtime-env"})
    for line_no, line in enumerate(text.splitlines(), 1):
        if URL_PASSWORD.search(line):
            findings.append({"path": path, "line": line_no, "rule": "database-url-password"})
        assignment = SECRET_ASSIGNMENT.match(line)
        type_declaration = assignment and path.endswith(".d.ts") and assignment.group(2).strip().rstrip(";") == "string"
        if assignment and not type_declaration and not is_empty_or_runtime_reference(assignment.group(2)):
            findings.append({"path": path, "line": line_no, "rule": "literal-auth-secret"})
        elif LITERAL.search(line):
            findings.append({"path": path, "line": line_no, "rule": "literal-auth-secret"})
    return findings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--staged", action="store_true")
    args = parser.parse_args()
    root = Path(args.repo).resolve()
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    result = []
    for path in filter(None, paths):
        if args.staged:
            try:
                raw = subprocess.check_output(["git", "show", ":" + path], cwd=root, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                continue
        else:
            target = root / path
            if not target.is_file():
                continue
            raw = target.read_bytes()
        if b"\0" not in raw:
            result.extend(scan(path, raw.decode("utf-8", "replace")))
    print(json.dumps({"findings": result, "count": len(result)}, ensure_ascii=True))
    return 1 if result else 0

if __name__ == "__main__":
    raise SystemExit(main())
