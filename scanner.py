"""Conservative illustrative static checks; not a replacement for Bandit/Semgrep."""
import re

EXTENSIONS = {".py": "python", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript", ".tsx": "typescript", ".sql": "sql", ".sh": "shell", ".java": "java", ".go": "go"}

RULES = [
    ("Embedded private key", "critical", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "A private key appears in the source.", "Revoke/rotate the exposed key and load secrets from a secret manager."),
    ("Possible hardcoded credential", "high", r"(?i)\b(?:password|passwd|api_key|secret_key|access_token)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]", "A credential-like literal is embedded in source.", "Use environment variables or a secret manager and rotate real exposed credentials."),
    ("Python dynamic execution", "high", r"\b(?:eval|exec)\s*\(", "Dynamic execution can run untrusted input.", "Avoid eval/exec; parse expected input with safe parsers."),
    ("Shell invocation", "high", r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\(.*shell\s*=\s*True", "Shell command execution can expose injection risk.", "Use argument arrays with shell=False and validate inputs."),
    ("Unsafe deserialization", "high", r"\bpickle\.loads?\s*\(", "Loading untrusted pickle data may execute code.", "Use JSON or another non-executable format for untrusted data."),
    ("Insecure TLS verification", "high", r"\bverify\s*=\s*False\b", "TLS certificate verification appears disabled.", "Enable certificate validation."),
    ("JavaScript document.write", "medium", r"\bdocument\.write\s*\(", "Writing untrusted content to HTML can cause XSS.", "Use textContent or a safe templating/sanitization method."),
    ("JavaScript innerHTML", "medium", r"\.innerHTML\s*=", "Setting innerHTML with untrusted data can cause XSS.", "Prefer textContent or sanitize with a reviewed library."),
]


def static_scan(code: str, language: str) -> list[dict]:
    """Find patterns; line numbers are one-based. Findings need human review."""
    found = []
    for n, line in enumerate(code.splitlines(), 1):
        if len(line) > 20000:
            continue
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "--", "*")) and "PRIVATE KEY" not in line:
            continue
        for title, severity, pattern, description, recommendation in RULES:
            # Rules geared to Python or JS are excluded for unrelated language families.
            if title in {"Python dynamic execution", "Shell invocation", "Unsafe deserialization", "Insecure TLS verification"} and language != "python":
                continue
            if title.startswith("JavaScript") and language not in {"javascript", "typescript"}:
                continue
            if re.search(pattern, line):
                found.append(dict(title=title, severity=severity, line=n, description=description, recommendation=recommendation, source="static"))
    return found[:100]
