# AI Security Starter Checklist

Five audit prompts for one LLM feature. Copy a prompt, then paste a design note or code you are allowed to share. These are defensive reviews: findings, evidence, and mitigations. They are not exploit instructions.

Work on a single feature at a time (one chat route, one ingest job, or one agent). Compare the model’s findings with the code before you file tickets.

---

## 1. Prompt injection and untrusted input

**When to use:** The feature puts user text, retrieved documents, web pages, tickets, email, or tool results into a model call, or it lets model output pick a tool, query, or URL.

**Prompt:**

```text
You are a defensive application-security reviewer. Review ONE LLM feature I will paste after this prompt. I am authorized to assess it.

Goal: see whether untrusted text can change instructions, tool choice, or downstream queries.

Treat as untrusted: user messages, RAG documents, web pages, file contents, email, tickets, and tool results. Developer-written system text is trusted only when it is a fixed string.

Check:
1. Are system or developer instructions stored separately from user and retrieved text (roles, structured fields, or clear delimiters)?
2. Can a document in the knowledge base, or a tool result, tell the model to ignore earlier instructions or to call a different tool?
3. Before any tool, SQL, shell, or HTTP call, is the argument checked against an allowlist the model cannot rewrite?
4. Are retrieved chunks labeled with source and a trust level the app actually enforces?
5. What still holds if one indexed document was written by an outsider?

Rules:
- Defensive review only. Do not write exploits, payloads, jailbreak strings, or attack procedures.
- Cite the file, function, or design note for every finding.
- Rate each finding High, Medium, or Low, and give one mitigation that can ship without a redesign.

Output:
- Two-sentence description of the feature
- Findings: severity, location, issue, mitigation
- Top three fixes in order
- Assumptions and questions
```

**Expected output:** A short description, a findings list with locations, and three ordered fixes. Typical fixes are a fixed system message, retrieval filters, and an allowlist before tool arguments. You should not receive sample attacks.

---

## 2. Secrets and credentials in LLM and RAG pipelines

**When to use:** Before commit or deploy, when prompts, notebooks, index jobs, vector-store clients, or agent tools touch API keys, database URLs, or cloud credentials.

**Prompt:**

```text
You are a defensive reviewer looking only for credential exposure in an LLM or RAG pipeline. I am authorized to assess the material I paste next.

Search the pasted code and config for:
1. API keys, tokens, passwords, or connection strings written in source, notebooks, fixtures, or checked-in env files.
2. Secrets interpolated into prompts, traces, analytics, or error messages.
3. Retrieval corpora, logs, or chat history that may contain customer credentials.
4. Clients created with a long-lived key where a short-lived, scoped credential would do.
5. Examples and tests that use real-looking keys instead of an obvious placeholder.

Rules:
- Defensive review only. Do not produce working credentials, crack hashes, or explain how to abuse a leaked key.
- Redact secret values in your answer (show at most a short prefix).
- Cite location, name the store that should hold the secret, and say who should rotate it if it may already have leaked.

Output:
- Findings: severity, location, redacted evidence, mitigation
- A short “safe to commit?” note: yes or no, and why
```

**Expected output:** A findings list with redacted evidence and a yes/no on whether the snippet is safe to commit. Remediation should name a secret manager or environment variable, plus rotation if a live value was present.

---

## 3. Over-broad tool and agent permissions

**When to use:** The feature can call tools, plugins, MCP servers, code execution, a browser, a shell, or internal APIs on behalf of a user.

**Prompt:**

```text
You are a defensive reviewer of tool and agent permissions. Review the single feature I paste next. I am authorized to assess it.

Map each tool the agent can call. For every tool, answer:
1. What is the worst action this tool can take with the credentials it actually receives?
2. Is the tool available to every user and every conversation, or is it scoped to a tenant, role, and task?
3. Are arguments allowlisted (hosts, SQL statements, file paths, function names), or does the model pass them through?
4. Can the agent add tools, change its own permissions, or follow instructions loaded from retrieved content?
5. Where would a human have to approve a destructive or irreversible action, and what happens if that check is missing?

Rules:
- Defensive review only. Do not write exploit steps, payloads, or weaponized tool calls.
- Separate “configured in code” from “assumed.”
- Prefer removing a tool or narrowing its scope over adding a warning in the prompt.

Output:
- Tool table: name, capability, credential scope, gap, mitigation
- The one permission you would remove or shrink first
```

**Expected output:** One row per tool, plus a single permission to remove or narrow. Look for wildcard tool lists, shared admin tokens, and tools whose arguments are not checked.

---

## 4. Logging, monitoring, and human approval

**When to use:** Before production, or when an agent can change data, spend money, send messages, or call internal APIs without a person in the loop.

**Prompt:**

```text
You are a defensive reviewer of logging, monitoring, and human approval for ONE agent or LLM feature. I am authorized to assess what I paste next.

Check:
1. Which actions are audited (tool name, actor, tenant, target resource, allow/deny, timestamp)? Are prompts and documents logged in full, and do those logs store secrets or customer content longer than necessary?
2. What would an on-call engineer see if the agent repeated a failing tool, fetched unusual volumes of data, or called an admin-only action?
3. Which actions require human approval, and is that approval enforced in code rather than only in the system prompt?
4. Can the agent proceed when the approval service times out or returns an error?
5. Are traces redacted before they leave the production environment?

Rules:
- Defensive review only. Do not describe how to disable controls or hide from monitoring.
- Cite the control or note that it is absent.
- Mark each gap High, Medium, or Low.

Output:
- Control list: present or missing, with location
- Three logging or approval changes, smallest first
- What an operator should alert on
```

**Expected output:** A present/missing control list, three small changes, and concrete alert ideas (repeated tool failures, admin tool use, approval bypass). Approval that exists only as prompt text should show up as a gap.

---

## 5. Threat model for a single AI feature

**When to use:** Early design, or a first security pass when you do not yet know which of the prompts above matters most.

**Prompt:**

```text
You are a defensive threat-modeling partner. Build a small threat model for the ONE AI feature I describe next. I am authorized to assess it.

Stay inside this feature. Do not invent a full enterprise model.

Cover:
1. Assets: model access, user data, retrieved documents, credentials the feature can use, and actions it can take.
2. Trust boundaries: user, prompt, retriever, model, tools, and any external site or SaaS.
3. Abusers who are in scope: a malicious user, a poisoned document in the corpus, a compromised tool response. Ignore nation-state scenarios.
4. For each boundary, what crosses it, and one realistic failure if that input is hostile.
5. Controls we already have versus controls that are missing.
6. The three risks that should be fixed before launch, ranked.

Rules:
- Defensive review only. Do not write exploits, payloads, or attack procedures.
- If I did not give a fact, list it under assumptions instead of guessing.
- Keep the result short enough to paste into a design doc.

Output:
- Feature summary (five lines or fewer)
- Boundaries and assets
- Ranked risks: scenario in one sentence, impact, missing control
- Three pre-launch fixes
- Open questions
```

**Expected output:** A one-feature threat model: assets, boundaries, ranked risks, and three fixes. Use it to decide which of prompts 1–4 to run next. Scenarios should stay at impact level, without reproduction steps.

---

These five prompts are the free starter. The commercial **AI Security & Infrastructure Prompt Pack** (62 prompts, 6 templates, 5 scripts) is sold separately by Digital Fortress: https://fortressaudit.gumroad.com/l/myyeen
