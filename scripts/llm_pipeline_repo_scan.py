#!/usr/bin/env python3
# Read-only local scanner for common LLM and RAG pipeline risks.
# Authorized defensive audits only. Does not write files or use the network.
# Digital Fortress — AI Security Starter Checklist
# https://fortressaudit.gumroad.com/l/myyeen

"""Scan a local repository for LLM and RAG risk patterns.

Looks for hardcoded credentials, overly broad tool or agent permissions,
unsafe deserialization, and agent-style HTTP routes that show no
authentication check nearby. Output is a report. The tree is never modified
and no network calls are made.

Run only against code you own or are permitted to audit.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}

SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".next",
        "vendor",
        "coverage",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "site-packages",
        ".eggs",
    }
)

SKIP_FILE_NAMES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Cargo.lock",
        "composer.lock",
        "Gemfile.lock",
    }
)

CODE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".go",
        ".php",
        ".java",
        ".rb",
    }
)

TEXT_SUFFIXES = CODE_SUFFIXES | frozenset(
    {
        ".json",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".env",
        ".txt",
        ".md",
        ".rst",
        ".sh",
        ".tf",
        ".xml",
        ".html",
        ".vue",
        ".svelte",
        ".properties",
    }
)

MAX_FILE_BYTES = 1_048_576
ROUTE_LOOKAHEAD = 40


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    path: str
    line: int
    message: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class LineRule:
    rule: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    recommendation: str


_PLACEHOLDER_VALUE = re.compile(
    r"(?ix)^(?:"
    r"your[-_a-z0-9]*"
    r"|example[-_a-z0-9]*"
    r"|changeme[-_a-z0-9]*"
    r"|placeholder[-_a-z0-9]*"
    r"|redacted"
    r"|dummy[-_a-z0-9]*"
    r"|sample[-_a-z0-9]*"
    r"|insert[-_a-z0-9]*"
    r"|todo"
    r"|xxx+"
    r"|none|null|undefined|false|true"
    r"|<[^>]+>"
    r")$"
)

_QUOTED_SECRET = re.compile(
    r"""(?ix)
    ['\"]?
    \b(
        (?:openai|anthropic|cohere|groq|huggingface|gemini|mistral|openrouter|aws)[_-]?
        (?:api[_-]?)?(?:key|token|secret)
        | api[_-]?key
        | secret[_-]?key
        | access[_-]?token
        | auth[_-]?token
        | client[_-]?secret
        | aws[_-]?(?:secret[_-]?access[_-]?key|access[_-]?key[_-]?id)
    )
    \b
    ['\"]?
    \s*[=:]\s*
    (['\"])([^'\"\n]{12,})\2
    """
)

_ENV_SECRET = re.compile(
    r"""(?ix)
    ^\s*(?:export\s+)?
    ([A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY)[A-Z0-9_]*)
    \s*=\s*
    (['\"]?)([^'\"\s\#]{12,})\2
    \s*(?:\#.*)?$
    """
)

# Longer prefixes must be listed before the generic sk- form.
_PROVIDER_KEY = re.compile(
    r"""(?x)
    (?<![A-Za-z0-9])(
        sk-ant-[A-Za-z0-9_\-]{20,}
        | sk-proj-[A-Za-z0-9_\-]{20,}
        | sk-[A-Za-z0-9]{20,}
        | hf_[A-Za-z0-9]{20,}
        | AKIA[0-9A-Z]{16}
        | ghp_[A-Za-z0-9]{20,}
        | github_pat_[A-Za-z0-9_]{20,}
        | xox[baprs]-[A-Za-z0-9\-]{10,}
    )
    (?![A-Za-z0-9])
    """
)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
)

_ROUTE_START = re.compile(
    r"""(?ix)
    @(?:[\w.]+)\.(?:route|get|post|put|patch|delete)\s*\(
    |
    \b(?:app|router|blueprint)\.(?:route|get|post|put|patch|delete)\s*\(
    """
)

# Match quoted route paths only, so header names like User-Agent do not count.
_LLM_ROUTE_HINT = re.compile(
    r"""(?ix)
    ['\"][^'\"]{0,120}
    (?:
        /(?:chat|agent|completions|invoke|rag|llm|prompts|tools)\b
        | \b(?:chat|agent|rag|llm)[_-]
    )
    [^'\"]*['\"]
    """
)

_AUTH_HINT = re.compile(
    r"""(?ix)
    login_required
    | requires_auth
    | require_auth
    | get_current_user
    | current_user
    | HTTPBearer
    | HTTPAuthorizationCredentials
    | Depends\s*\(
    | \bjwt\b
    | authorize
    | requireAuth
    | authMiddleware
    | verify_token
    | verifyToken
    | isAuthenticated
    | authenticated
    | \boauth\b
    | api[_-]?key[_-]?auth
    | ensureLoggedIn
    | req\.user
    | request\.user
    """
)

LINE_RULES: tuple[LineRule, ...] = (
    LineRule(
        rule="permissive_tool_wildcard",
        severity="high",
        pattern=re.compile(
            r"""(?ix)
            (?:allowed_tools|enabled_tools|tools|always_allow|alwaysAllow|allowedTools)
            \s*[=:]\s*
            (?:
                \[\s*['\"]\*['\"]\s*\]
                | ['\"]\*['\"]
                | ['\"]all['\"]
            )
            """
        ),
        message="Tool list allows every tool.",
        recommendation="Name the tools this feature needs. Drop the wildcard and review each remaining tool.",
    ),
    LineRule(
        rule="trust_remote_code",
        severity="high",
        pattern=re.compile(r"(?i)\btrust_remote_code\s*[=:]\s*(?:True|true|1)\b"),
        message="Remote code from a model or dataset repo is trusted.",
        recommendation="Leave trust_remote_code off unless you pin a repo you control and review its code.",
    ),
    LineRule(
        rule="code_execution_enabled",
        severity="high",
        pattern=re.compile(
            r"(?i)\b(?:allow_dangerous_code|enable_code_execution|allow_code_execution)\s*[=:]\s*(?:True|true|1)\b"
        ),
        message="Code execution is enabled for the model or agent.",
        recommendation="Disable code execution unless a sandbox and a human approval step both sit in front of it.",
    ),
    LineRule(
        rule="model_output_eval",
        severity="high",
        pattern=re.compile(
            r"(?i)\b(?:eval|exec)\s*\(\s*(?:response|completion|llm_output|model_output|result\.content|message\.content)\b"
        ),
        message="Model output is passed to eval or exec.",
        recommendation="Treat model output as data. Parse a structured result and allowlist the actions you run.",
    ),
    LineRule(
        rule="approval_disabled",
        severity="medium",
        pattern=re.compile(
            r"(?i)\b(?:human_in_the_loop|require_human_approval|require_approval|require_confirmation)\s*[=:]\s*(?:False|false|0)\b"
        ),
        message="Human approval is turned off in configuration.",
        recommendation="Require approval in code for irreversible or privileged tool calls, not only in the prompt.",
    ),
    LineRule(
        rule="code_or_shell_tool",
        severity="medium",
        pattern=re.compile(r"(?i)\b(?:PythonREPLTool|ShellTool|BashProcess|TerminalTool)\s*\("),
        message="A shell or code-execution tool is constructed.",
        recommendation="Sandbox the tool, scope its credentials, and require approval before it runs.",
    ),
    LineRule(
        rule="pickle_load",
        severity="medium",
        pattern=re.compile(r"(?i)\bpickle\.loads?\s*\("),
        message="pickle.load can run code while deserializing.",
        recommendation="Do not unpickle model artifacts, indexes, or uploads you do not fully control. Use a safe format.",
    ),
    LineRule(
        rule="torch_load_unsafe",
        severity="medium",
        pattern=re.compile(
            r"(?i)\btorch\.load\s*\((?![^)\n]*weights_only\s*=\s*True)"
        ),
        message="torch.load is called without weights_only=True.",
        recommendation="Pass weights_only=True unless you have reviewed this checkpoint and accept code execution on load.",
    ),
    LineRule(
        rule="system_prompt_interpolation",
        severity="medium",
        pattern=re.compile(
            r"""(?ix)
            (?:system(?:_prompt|_message)?|SYSTEM)
            \s*[=:]
            \s*f['\"][^'\n]*\{
            (?:user(?:_input|_message|_text)?|query|request|prompt|message|content|document|context)\b
            """
        ),
        message="A system prompt interpolates data that may be untrusted.",
        recommendation="Keep the system text static. Pass user and retrieved text in a separate message.",
    ),
    LineRule(
        rule="url_loader_from_request",
        severity="medium",
        pattern=re.compile(
            r"""(?ix)
            \b(?:WebBaseLoader|UnstructuredURLLoader|SeleniumURLLoader|AsyncHtmlLoader|PlaywrightURLLoader)
            \s*\(\s*(?:request|req|user|query|url|params|body)\b
            """
        ),
        message="A URL document loader is given request or user data.",
        recommendation="Allowlist hosts, and treat fetched page text as untrusted input to the model.",
    ),
)


def is_placeholder(value: str) -> bool:
    """Return True when a matched value is an obvious fake or a variable reference."""
    text = value.strip()
    if any(token in text for token in ("${", "process.env", "os.environ", "getenv(", "ENV[")):
        return True
    if _PLACEHOLDER_VALUE.match(text):
        return True
    core = re.sub(r"[^A-Za-z0-9]", "", text)
    if core and len(set(core)) == 1:
        return True
    return False


def is_scannable(path: Path) -> bool:
    name = path.name
    if name in {"Dockerfile", "Makefile", "Jenkinsfile", "Containerfile"}:
        return True
    if name == ".env" or name.startswith(".env"):
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def sensitive_filename(name: str) -> str | None:
    lower = name.lower()
    if lower == ".env" or (
        lower.startswith(".env.")
        and not any(part in lower for part in ("example", "sample", "template"))
    ):
        return "committed_env_file"
    if lower in {"credentials.json", "service-account.json", "serviceaccount.json"} or lower.endswith(
        "-credentials.json"
    ):
        return "credential_filename"
    if "id_rsa" in lower or lower.endswith(".pem") or lower.endswith(".p12"):
        return "key_material_filename"
    return None


def add_finding(
    findings: list[Finding],
    *,
    severity: str,
    rule: str,
    path: str,
    line: int,
    message: str,
    recommendation: str,
) -> None:
    findings.append(
        Finding(
            severity=severity,
            rule=rule,
            path=path,
            line=line,
            message=message,
            recommendation=recommendation,
        )
    )


def scan_secrets(rel: str, lineno: int, line: str, findings: list[Finding]) -> None:
    if _PRIVATE_KEY.search(line):
        add_finding(
            findings,
            severity="high",
            rule="private_key",
            path=rel,
            line=lineno,
            message="Private key material is present in the file.",
            recommendation="Remove the key from the tree, rotate it, and load it from a secret manager.",
        )
        return

    quoted = _QUOTED_SECRET.search(line)
    if quoted and not is_placeholder(quoted.group(3)):
        add_finding(
            findings,
            severity="high",
            rule="hardcoded_secret",
            path=rel,
            line=lineno,
            message=f"Hardcoded credential assigned to {quoted.group(1)} (value redacted).",
            recommendation="Remove the value from source, rotate it if it was real, and read it from the environment or a secret manager.",
        )
        return

    env = _ENV_SECRET.search(line)
    if env and not is_placeholder(env.group(3)):
        add_finding(
            findings,
            severity="high",
            rule="hardcoded_secret",
            path=rel,
            line=lineno,
            message=f"Hardcoded credential assigned to {env.group(1)} (value redacted).",
            recommendation="Remove the value from source, rotate it if it was real, and read it from the environment or a secret manager.",
        )
        return

    provider = _PROVIDER_KEY.search(line)
    if provider and not is_placeholder(provider.group(1)):
        add_finding(
            findings,
            severity="high",
            rule="provider_key",
            path=rel,
            line=lineno,
            message="Provider or platform API key pattern found (value redacted).",
            recommendation="Rotate the key, remove it from the repository, and inject it at runtime.",
        )


def route_block(lines: list[str], index: int) -> str:
    """Return the decorator and signature, stopping before the next route."""
    selected = [lines[index]]
    saw_def = False
    limit = min(len(lines), index + 1 + ROUTE_LOOKAHEAD)
    for follow in lines[index + 1 : limit]:
        if _ROUTE_START.search(follow):
            break
        selected.append(follow)
        if re.search(r"(?i)\b(?:async\s+)?def\s+\w+\s*\(", follow) or re.search(
            r"(?i)\bfunction\s+\w+\s*\(", follow
        ):
            saw_def = True
            if follow.rstrip().endswith(":"):
                break
        elif saw_def and follow.rstrip().endswith(":"):
            break
        elif re.search(r"\)\s*(?:=>|\{)\s*$", follow):
            break
    return "\n".join(selected)


def scan_routes(rel: str, lines: list[str], findings: list[Finding]) -> None:
    if Path(rel).suffix.lower() not in CODE_SUFFIXES:
        return
    for index, line in enumerate(lines):
        if not _ROUTE_START.search(line):
            continue
        block = route_block(lines, index)
        if not _LLM_ROUTE_HINT.search(block):
            continue
        if _AUTH_HINT.search(block):
            continue
        add_finding(
            findings,
            severity="medium",
            rule="agent_route_auth_not_visible",
            path=rel,
            line=index + 1,
            message="Agent or LLM route has no authentication check in the handler signature.",
            recommendation="Enforce authentication in code or middleware, and authorize the tenant and the tools this route can call.",
        )


def scan_lines(rel: str, lines: list[str], findings: list[Finding]) -> None:
    for index, line in enumerate(lines, start=1):
        scan_secrets(rel, index, line, findings)
        for rule in LINE_RULES:
            if rule.pattern.search(line):
                add_finding(
                    findings,
                    severity=rule.severity,
                    rule=rule.rule,
                    path=rel,
                    line=index,
                    message=rule.message,
                    recommendation=rule.recommendation,
                )
    scan_routes(rel, lines, findings)


def read_text(path: Path) -> list[str] | None:
    """Read a file for scanning. Return None when it should be skipped."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    try:
        with path.open("rb") as handle:
            blob = handle.read()
    except OSError:
        return None
    if b"\0" in blob[:1024]:
        return None
    return blob.decode("utf-8", errors="replace").splitlines()


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in SKIP_DIR_NAMES and not (Path(dirpath) / name).is_symlink()
        ]
        for name in filenames:
            if name in SKIP_FILE_NAMES:
                continue
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            yield path


def scan(root: Path) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    files_scanned = 0
    skipped = 0

    for path in iter_files(root):
        rel = path.name if root.is_file() else str(path.relative_to(root))
        filename_rule = sensitive_filename(path.name)
        if filename_rule == "committed_env_file":
            add_finding(
                findings,
                severity="medium",
                rule=filename_rule,
                path=rel,
                line=1,
                message="Environment file is present in the tree.",
                recommendation="Keep secrets out of git. Commit a template with placeholders, and load real values at runtime.",
            )
        elif filename_rule:
            add_finding(
                findings,
                severity="medium",
                rule=filename_rule,
                path=rel,
                line=1,
                message="Filename looks like credential or key material.",
                recommendation="Confirm this file is meant to be public. Prefer a secret manager for private keys and service accounts.",
            )

        if not is_scannable(path):
            continue
        lines = read_text(path)
        if lines is None:
            skipped += 1
            continue
        files_scanned += 1
        scan_lines(rel, lines, findings)

    stats = {"files_scanned": files_scanned, "skipped": skipped, "findings": len(findings)}
    return findings, stats


def format_text(root: Path, findings: list[Finding], stats: dict[str, int]) -> str:
    counts = {name: 0 for name in SEVERITY_RANK}
    for finding in findings:
        counts[finding.severity] += 1
    lines = [
        f"LLM pipeline scan: {root}",
        (
            f"Files scanned: {stats['files_scanned']}  "
            f"skipped: {stats['skipped']}  "
            f"findings: {stats['findings']} "
            f"(high={counts['high']}, medium={counts['medium']}, low={counts['low']})"
        ),
    ]
    if not findings:
        lines.append("No matching risk patterns.")
        return "\n".join(lines) + "\n"
    ordered = sorted(findings, key=lambda item: (SEVERITY_RANK[item.severity] * -1, item.path, item.line, item.rule))
    for finding in ordered:
        lines.append("")
        lines.append(f"[{finding.severity.upper()}] {finding.rule} {finding.path}:{finding.line}")
        lines.append(f"  {finding.message}")
        lines.append(f"  Fix: {finding.recommendation}")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only scan of a local repo for LLM/RAG risk patterns. "
            "Does not modify files or use the network. Authorized audits only."
        )
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory)",
    )
    parser.add_argument("--json", action="store_true", help="Print findings as JSON")
    parser.add_argument(
        "--fail-on",
        choices=("high", "medium", "low", "never"),
        default="high",
        help="Exit 1 when a finding at or above this severity exists (default: high)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 2
    findings, stats = scan(root)
    if args.json:
        payload = {
            "root": str(root),
            "files_scanned": stats["files_scanned"],
            "skipped": stats["skipped"],
            "findings": [finding.to_dict() for finding in findings],
        }
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(format_text(root, findings, stats))
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    if any(SEVERITY_RANK[item.severity] >= threshold for item in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
