# AI Security Starter Checklist

Free checks for teams shipping an LLM feature: **five copy-paste audit prompts** and **one read-only repository scan**. Use them on systems you own or are explicitly allowed to review.

**Want the full pack?** [AI Security & Infrastructure Prompt Pack ($99)](https://fortressaudit.gumroad.com/l/myyeen) — 62 prompts, 6 templates, and 5 scripts, including MCP tool poisoning, OWASP agentic threats, MAESTRO, and Kubernetes/cloud reviews. Sold at [fortressaudit.gumroad.com](https://fortressaudit.gumroad.com).

The prompts live in [CHECKLIST.md](CHECKLIST.md). The scanner is [scripts/llm_pipeline_repo_scan.py](scripts/llm_pipeline_repo_scan.py). It looks for hardcoded credentials, broad tool permissions, and agent-style routes with no authentication check nearby. It only reads files.

## Authorized use

This repository is [MIT licensed](LICENSE). It is for **defensive audits only**.

- Review applications, pipelines, and configs you own or are authorized to assess.
- The prompts ask for findings, evidence, and mitigations. They do not include exploit steps, payloads, or attack procedures.
- Do not point the scanner at systems you are not allowed to inspect. It does not change files and it does not use the network, but the report can describe sensitive paths.

## How to use the prompts

1. Open [CHECKLIST.md](CHECKLIST.md) and pick the prompt that matches the risk you care about.
2. Paste the prompt into the model you use for code review.
3. Paste the design note or source you are allowed to share. Strip production secrets first. Prefer a private model endpoint if the code is sensitive.
4. Read the findings against the real code. The model can miss context and can over-call risk. Keep what you can reproduce.

Run one prompt per feature. A chat handler, a RAG ingest job, and an agent tool loop are three reviews, not one.

## How to run the script

Requires Python 3.9 or newer. No third-party packages.

```bash
python3 scripts/llm_pipeline_repo_scan.py /path/to/your/repo
```

Scan the current directory and print machine-readable results:

```bash
python3 scripts/llm_pipeline_repo_scan.py --json .
```

Exit status is `1` when a **high** finding is present, so the script can run in CI. Other values:

| Flag | Behavior |
| --- | --- |
| `--fail-on high` | Default. Exit `1` only for high findings. |
| `--fail-on medium` | Exit `1` for medium or high. |
| `--fail-on low` | Exit `1` for any finding. |
| `--fail-on never` | Always exit `0`. Still prints the report. |

The script skips `.git`, dependency folders, lockfiles, binaries, and files larger than 1 MB. Secret values are redacted in the report. Rotate anything it flags, and move credentials to an environment variable or a secret manager.

Patterns are heuristics. A clean run is not a pentest. A hit on a route means “no auth check was visible nearby,” which is also true when auth lives in middleware. Confirm before you treat it as a bug.

## What you get here

| Piece | Role |
| --- | --- |
| Five prompts | Injection handling, secrets in LLM/RAG paths, tool permissions, logging and human approval, and a one-feature threat model |
| One script | Read-only scan of a local tree |

Templates, the other four scripts, and the remaining prompts are only in the paid pack.

## Full pack

Digital Fortress publishes the **AI Security & Infrastructure Prompt Pack** for people who want the rest of the review set: MCP tool poisoning, OWASP agentic threats, MAESTRO, Kubernetes and cloud, plus templates and scripts that are not in this repo.

**[Get the pack ($99)](https://fortressaudit.gumroad.com/l/myyeen)** at [fortressaudit.gumroad.com](https://fortressaudit.gumroad.com).

## License

[MIT](LICENSE) © 2026 Digital Fortress / digitalfortressaudit. Authorized defensive use only, as described above.
