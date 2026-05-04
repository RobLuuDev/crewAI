# Security Review — robluudev/crewai

**Branch:** `claude/document-repo-security-pidtE`  
**Date:** 2026-05-04  
**Reviewer:** Claude Code (automated security review)  
**Scope:** Full codebase under `lib/` — source files only (tests excluded from findings unless noted)

---

## Executive Summary

The codebase demonstrates a mature security posture for an open-source AI framework. Dependency management is exemplary, credential storage is well-implemented, and no `shell=True` subprocess calls exist anywhere in production code. Two higher-severity issues warrant attention: unsafe pickle deserialization and an agent-controllable SQL injection path in `DatabricksQueryTool`. Several lower-severity issues and one configuration concern are also documented.

---

## Findings

### HIGH — Pickle Deserialization Without Integrity Verification

**File:** `lib/crewai/src/crewai/utilities/file_handler.py:180`

```python
return pickle.load(file)  # noqa: S301
```

The `PickleHandler` class loads `.pkl` files from `os.getcwd()`. Pickle is inherently unsafe — a crafted `.pkl` file executes arbitrary Python on load. If an attacker can write to the working directory (e.g., via a malicious tool output, path traversal in a file-writing tool, or a compromised shared environment), they can achieve remote code execution when the handler next loads the file.

**Affected callers:** crew memory, training data, task replay state.

**Recommendation:** Replace `pickle` with `json` or `msgpack` for all stored state, or at minimum verify a HMAC/SHA-256 digest of the file before loading. If pickle must remain for compatibility, validate the file path is within an expected directory using `os.path.realpath()` and refuse files not owned by the current user.

---

### HIGH — Agent-Controllable SQL Injection via DatabricksQueryTool

**File:** `lib/crewai-tools/src/crewai_tools/tools/databricks_query_tool/databricks_query_tool.py:38-68`

The `DatabricksQueryTool` accepts a raw `query: str` field that is passed directly to the Databricks SQL statement execution API. The only validation performed is an emptiness check and automatic addition of a `LIMIT` clause. An agent that has been manipulated via prompt injection can craft any SQL statement — including `DROP TABLE`, `SELECT * FROM credentials`, data exfiltration via side channels, or privilege escalation if the configured service principal has broad permissions.

**Prompt injection chain:** external document → agent → tool call → arbitrary SQL on production Databricks.

**Recommendation:**
- Enforce a SQL read-only allowlist (e.g., only `SELECT` statements; reject DDL/DML at the tool level before execution).
- Apply least-privilege: the Databricks service principal should have `SELECT` on specific catalogs only.
- Log all executed queries with the agent's identity for audit purposes.

---

### MEDIUM — Committed `.env.test` File

**File:** `.env.test`

A `.env.test` file containing 40+ environment variable names is committed to the repository. All current values are clearly fake (`fake-api-key`, `fake-aws-secret-key`, etc.). The risks are:

1. **Fork contamination**: Any fork that populates this file with real credentials and accidentally pushes it would expose those credentials.
2. **Inventory disclosure**: The file reveals the full set of third-party integrations (BrightData, Apify, Oxylabs, Snowflake, SingleStore, Databricks, Weaviate, etc.), providing a useful attack surface map to an adversary.
3. **CI misconfiguration risk**: A CI pipeline that mistakenly uses this file as a template with real secrets would commit credentials to history.

**Recommendation:** Add `.env.test` to `.gitignore` and distribute it via a `.env.test.example` template with placeholder comments instead of fake-looking values. Alternatively, document that fake values are intentional with a header comment in the file itself (currently absent).

---

### MEDIUM — Unencrypted `http://` Channel Allowed in A2A gRPC Delegation

**File:** `lib/crewai/src/crewai/a2a/utils/delegation.py:824`

```python
elif url.startswith("http://"):
    target = url[7:]
    # use_tls remains False — no TLS channel established
```

When an agent card URL begins with `http://`, the gRPC delegation creates a plaintext channel without TLS. Agent-to-agent communication over this channel exposes task context, intermediate results, and potentially credentials passed as task inputs to network interception.

**Recommendation:** Reject `http://` URLs for production A2A agent cards. Add a configuration flag (e.g., `allow_insecure=False`) that must be explicitly set to `True` for development environments. Log a prominent warning when plaintext channels are used.

---

### LOW — `ast.literal_eval` Fallback on LLM-Produced Tool Input

**File:** `lib/crewai/src/crewai/tools/tool_usage.py:881`

```python
arguments = ast.literal_eval(tool_input)
```

`ast.literal_eval` is safe against code execution, but it accepts Python literal syntax including tuples, sets, and bytes objects that are not valid JSON. If a downstream tool expects a `dict` but receives a `tuple` from this path, it may produce incorrect behaviour that is difficult to trace. More importantly, an LLM that produces output like `{"key": (1, 2)}` will succeed through `literal_eval` but silently break JSON-round-trip assumptions.

**Recommendation:** After `literal_eval`, assert the result is a `dict`. If not, raise a `ValueError` and fall through to the `json5` repair path.

---

### LOW — Telemetry Enabled by Default

**File:** `lib/crewai/src/crewai/telemetry/telemetry.py:151-152`

Telemetry is active unless `OTEL_SDK_DISABLED=true` or `CREWAI_DISABLE_TELEMETRY=true` is set. While the README and source confirm no prompts, task descriptions, or secrets are transmitted, the data collected includes: agent roles, tool names, crew process type, LLM provider identifiers, and OS/hardware fingerprinting (via `system_profiler` on macOS and `wmic` on Windows). In air-gapped or classified environments this default-on behaviour may violate policy.

**Recommendation:** Document the telemetry default prominently in the installation guide, and consider adding a first-run prompt asking users to opt in rather than opt out. The `CREWAI_DISABLE_TELEMETRY` variable should be documented alongside `OTEL_SDK_DISABLED` in the README (currently only the latter is mentioned).

---

## Positive Security Controls

The following security practices are well-implemented and should be preserved:

| Control | Location | Notes |
|---|---|---|
| No `shell=True` anywhere | All CLI subprocess calls | All use list-form args; S603 suppressions are appropriate |
| `yaml.safe_load()` throughout | `skills/parser.py`, `project/crew_base.py` | No unsafe YAML deserialisation |
| Fernet-encrypted token storage | `cli/shared/token_manager.py` | 0o600 file permissions, atomic writes, tempfile-based updates |
| HMAC-SHA256 webhook signatures | `a2a/config.py`, `a2a/updates/push_notifications/signature.py` | `SecretStr` prevents accidental logging |
| Explicit CVE pins in `pyproject.toml` | `[tool.uv]` `override-dependencies` | 12+ CVEs documented with links; exemplary practice |
| `pip-audit` in dev dependencies | `pyproject.toml` | Enables automated dependency auditing in CI |
| Bandit + ruff-S security linting | `pyproject.toml` | Runs in pre-commit |
| `exclude-newer` snapshot | `[tool.uv]` | Time-bounds dependency resolution to a known-good date |
| `SecretStr` for credentials in A2A | `a2a/auth/client_schemes.py` | Prevents credentials from appearing in `repr()` / logs |

---

## Dependency Security Notes

`pyproject.toml` already pins remediated versions for:

- `litellm` SSTI (`GHSA-xqmj-j6mv-4862`) → ≥1.83.7
- `langchain-core` RCE (`GHSA-926x-3r5x-gfhw`) → ≥1.2.31
- `langchain-text-splitters` SSRF (`GHSA-fv5p-p927-qmxr`) → ≥1.1.2
- `transformers` (`CVE-2026-1839`) → ≥5.4.0
- `cryptography` (`CVE-2026-39892`) → ≥46.0.7
- `pypdf` (3 CVEs) → ≥6.10.2
- `python-multipart` (`GHSA-mj87-hwqh-73pj`) → ≥0.0.26
- `authlib` (`GHSA-jj8c-mmj3-mmgv`) → ≥1.6.11
- `langsmith` (`GHSA-rr7j-v2q5-chgv`) → ≥0.7.31

No outstanding unaddressed CVEs were identified in pinned transitive dependencies at the time of this review.

---

## Recommended Actions (Priority Order)

1. **[HIGH]** Replace `pickle.load` in `PickleHandler` with a safe serialization format and/or add HMAC integrity verification.
2. **[HIGH]** Add SQL statement type validation to `DatabricksQueryTool` to reject non-`SELECT` statements.
3. **[MEDIUM]** Add `.env.test` to `.gitignore`; replace with `.env.test.example`.
4. **[MEDIUM]** Reject plaintext `http://` URLs in A2A gRPC delegation or add an explicit `allow_insecure` opt-in.
5. **[LOW]** Assert `isinstance(result, dict)` after `ast.literal_eval` in `tool_usage.py`.
6. **[LOW]** Document `CREWAI_DISABLE_TELEMETRY` in the README alongside `OTEL_SDK_DISABLED`.
