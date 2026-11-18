# AgentScope - Arbitrary DB-Path File Creation and SQL Execution Surface in `AsyncSQLAlchemyStorage` (Unvalidated Connection URL)

![CVE](https://img.shields.io/badge/CVE-PENDING-lightgrey)
![CVSS](https://img.shields.io/badge/CVSS_3.1-7.4_High-orange)
![CWE](https://img.shields.io/badge/CWE--73-External_Control_of_File_Name_or_Path-red)
![CWE](https://img.shields.io/badge/CWE--918-SSRF_class_outbound_surface-red)
![Status](https://img.shields.io/badge/status-draft-yellow)

> **Summary** - AgentScope's SQL storage backend hands the SQLAlchemy
> connection URL it is constructed with straight to `create_async_engine`,
> with no validation of the scheme, the file path, or the host - and then, on
> every SQLite connection it opens, runs `PRAGMA foreign_keys=ON` through a
> `connect` callback. Because the URL is a documented constructor parameter of
> a deployment component (`create_app(storage=AsyncSQLAlchemyStorage(url=...))`),
> any party that can influence it makes the *server* create or open a database
> file at an arbitrary path (CWE-73) and execute SQL on a connection the
> attacker selected. Measured on an unmodified AgentScope **2.0.11** Agent
> Service: a real REST call (`POST /credential/` -> `201`) caused a database
> file to appear at an attacker-chosen path outside the application data
> directory; the statement trace captured `PRAGMA foreign_keys=ON` executing
> on that connection and the pragma reads back `1`; and a
> `postgresql+asyncpg://...` URL was parsed and routed verbatim to an
> attacker-chosen `host:port`, whose listening socket received the startup
> packet.

Internal tracking ID: `AS-2026-004`.

<!--
  STATUS - 2026-11-18: draft. No CVE ID requested yet and the vendor has not
  been contacted. Update the badges, the Metadata "Status" row, the Timeline and
  the "Disclosure" section as soon as you file the report, and do not claim a
  submission happened before it did.
-->

## Metadata

| Field | Value |
|---|---|
| Vendor | AgentScope (`agentscope-ai`) |
| Product | AgentScope - Agent Service / SQL storage (`agentscope` PyPI package) |
| Repository | https://github.com/agentscope-ai/agentscope |
| Component | `src/agentscope/app/storage/_sql/_storage.py` - `AsyncSQLAlchemyStorage.__init__` / `__aenter__` / `_enable_sqlite_fk` |
| Affected version | `2.0.11` (PyPI, released 2026-10-27) - **confirmed affected**, code path below |
| Not tested | `2.0.12` (released 2026-11-16) and `main`; the URL is documented as the normal way to point the storage at any SQLite file or remote DBMS, so re-check before assuming it is fixed |
| Vulnerability class | CWE-73 (External Control of File Name or Path); SSRF-class outbound surface (CWE-918) when an async DB driver is installed |
| CVSS 3.1 (recommended, measured effects) | **7.4 High** - `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L` |
| CVSS 3.1 (with UNC/NTLM capture, `[Likely]`) | 9.1 Critical - `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L` |
| Status | Draft - no CVE ID requested yet |
| Reporter | gaoxihan (<https://github.com/taalsa>) |

## Summary

AgentScope ships an **Agent Service** (a FastAPI backend) whose state -
sessions, credentials, messages - lives in a SQL database. The documented
backend for it is `AsyncSQLAlchemyStorage`, constructed with a single
required argument:

```python
storage = AsyncSQLAlchemyStorage(
    url="sqlite+aiosqlite:///./as.db",   # ANY SQLAlchemy async URL
    ...                                   # create_tables=True by default
)
app = create_app(storage=storage)         # documented assembly
```

The docstring itself lists `'sqlite+aiosqlite:///./as.db'` and
`'postgresql+asyncpg://user:pw@host/db'` as the example values - the URL's
scheme, **file path**, **host**, **port** and credentials are all supplied by
whoever configures the component, and nothing in the class inspects any of it:

```python
self._url = url                            # L156  stored, zero validation
...
self._engine = create_async_engine(        # L180  the string goes to the engine
    self._url, future=True, **self._engine_kwargs,
)
if self._engine.sync_engine.dialect.name == "sqlite":
    @event.listens_for(self._engine.sync_engine, "connect")
    def _enable_sqlite_fk(dbapi_conn, _rec):        # L193  fires per connection
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")    # L195  SQL on that connection
```

Two properties make this a defect rather than a configuration-discipline
question:

1. **The URL is treated as trusted, but it is an input.** In BYO-DB,
   multi-tenant, or config-injection deployments the value can come from a
   lower-privileged party (tenant settings, an admin UI field, an upstream API
   that builds the storage per request). Whatever it names - a path, a host -
   is what the *server* opens.
2. **The consequence is code execution against the attacker's chosen target.**
   The SQLite `connect` callback runs a SQL statement on the connection the URL
   produced. The statement text is fixed - this is *not* SQL injection - but
   its **execution point** is attacker-selected: SQL runs on the attacker's
   database file, and (with a remote dialect) the engine dials the attacker's
   host.

## Root cause

Sink, in the audited 2.0.11 snapshot (line numbers shift a few lines across
builds; the quoted statements are the anchor):

```python
class AsyncSQLAlchemyStorage(...):

    def __init__(                              # L111
        self,
        url: str,                              # L113  TAINT SOURCE (documented arg)
        *,
        create_tables: bool = True,            # L129
        auto_migrate: bool = False,            # L130
        engine: AsyncEngine | None = None,     # L131  url ignored only if engine given
        engine_kwargs: dict[str, Any] | None = None,
    ) -> None:
        """...
        url (`str`):
            A SQLAlchemy async URL (e.g. `'sqlite+aiosqlite:///./as.db'`,
            `'postgresql+asyncpg://user:pw@host/db'`). Ignored when
            `engine` is provided.                          # L125-128
        """
        self._url = url                        # L156  stored, zero validation
        self._create_tables = create_tables    # L157

    async def __aenter__(self):                # L167
        ...
        self._engine = create_async_engine(    # L180-184  SINK of the URL
            self._url, future=True, **self._engine_kwargs,
        )
        self._owns_engine = True
        # SQLite ignores foreign keys unless enabled per connection, ...
        if self._engine.sync_engine.dialect.name == "sqlite":   # L189-190
            from sqlalchemy import event
            @event.listens_for(self._engine.sync_engine, "connect")  # L192
            def _enable_sqlite_fk(dbapi_conn, _rec):           # L193
                cursor = dbapi_conn.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")       # L195  SQL SINK
                cursor.close()
        ...
        if self._auto_migrate:                                 # L207-208
            await self._run_alembic_upgrade()                  #   same URL risk
        if self._create_tables:                                # L210-212
            async with self._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)  #   tables on the
                                                               #   chosen target
        return self
```

**Taint chain**

```
url (constructor: deployment config / tenant settings / upstream API)
    |
AsyncSQLAlchemyStorage(url)                       # L156  self._url = url, unvalidated
    |
create_async_engine(self._url, ...)               # L180  scheme -> dialect,
    |                                               #       path -> file, host -> socket
dialect.name == "sqlite"                          # L189
    |
@event.listens_for(..., "connect")                # L192  registered unconditionally
    |
cursor.execute("PRAGMA foreign_keys=ON")          # L195  SQL executed on the
                                                    #       attacker-selected connection
```

The side-effect branches ride the same unvalidated URL: `create_tables=True`
is the **default**, so `Base.metadata.create_all` runs against the
attacker-selected database (L210-212), and the `auto_migrate` branch runs an
Alembic upgrade on it (L207-208).

![Sink](screenshots/01-sink-storage-enable-sqlite-fk.png)

*Figure 1 - the sink. `L192-195`: the `connect` callback is registered
whenever the dialect is SQLite and executes `PRAGMA foreign_keys=ON` on every
pooled connection. `L180-184`: the caller's URL goes to `create_async_engine`
unchanged.*

![Taint source](screenshots/02-taint-source-constructor-url.png)

*Figure 2 - `__init__`. `url` is the required, documented constructor
parameter (the docstring's own examples include an arbitrary file path and a
remote host); `L156` stores it with no validation.*

## Who can influence the `url` (prerequisites, stated plainly)

This is not a claim that a remote attacker types the URL into the chat box.
The defect is that the component has **no boundary between "the connection
string" and "trusted configuration"**, so every channel that can affect that
string becomes a full-impact path:

| Channel | What it gives an attacker | Effect |
|---|---|---|
| Deployment config / env var / admin UI that sets the storage URL (the documented use) | arbitrary file path **+** arbitrary DB host | all measured effects |
| A multi-tenant wrapper that builds `AsyncSQLAlchemyStorage` per tenant from tenant-supplied settings (the framework's own extension point) | as above, per tenant | all measured effects |
| Application code that lets user data reach the URL (template, registry lookup, "bring your own database" feature) | as above | all measured effects |
| No URL influence at all (URL hard-pinned by the operator) | none | not exploitable |

The rating uses `PR:L`: reaching the first two channels normally needs some
privilege, not administrator rights. Where a deployment genuinely passes a
user-controlled value into the URL, `PR:N` (9.9) applies - see the CVSS table.

## Attack chain

![Chain](screenshots/04-attack-chain.png)

*Figure 3 - the chain used in the real-deployment test: `exp_real_api.py`
talks only to the product's own documented REST API of an **unmodified**
Agent Service; the sink is reached in-process, no test endpoint or patched
code is involved.*

```
attacker-chosen DB URL
        |
POST /credential/  (real REST on :8000, unmodified service)
        |
AsyncSQLAlchemyStorage.__aenter__ -> create_async_engine(url)
        |
connect callback -> cursor.execute("PRAGMA foreign_keys=ON")
        |
file created at the attacker's path / startup packet at the attacker's host
```

Measured and `[Likely]` effects:

| # | Effect | Status | Evidence |
|---|---|---|---|
| 1 | **Arbitrary-path DB file creation** - the file named by the URL goes from absent to created (12,288 bytes) outside the application data directory, driven by a real REST call (`POST /credential/` -> `201`) | **Verified** | Figures 4, 5, 6; `evidence/exp_real_api.log` |
| 2 | **SQL executed on the attacker-selected connection** - the trace captured `PRAGMA foreign_keys=ON` on that connection; the pragma reads back `1` on the same connection | **Verified** | Figure 8; `evidence/exp_storage_sql.log` |
| 3 | **Arbitrary scheme / host accepted** - `postgresql+asyncpg://...@127.0.0.1:18847/db` is parsed to the postgres dialect and the listener at that `host:port` received the asyncpg startup packet (`8 b'\x00\x00\x00\x08\x04\xd2\x16/'`) | **Verified** | Figures 5, 6; `evidence/exp_real_api.log` |
| 4 | **Schema written to the attacker-selected database** - `create_tables=True` (the default) runs `create_all` on whatever the URL names | **Verified** (statement traced in the self-contained run) | `evidence/exp_storage_sql.log` |
| 5 | **UNC path -> SMB -> NetNTLM hash capture** on Windows (`sqlite+aiosqlite:////attacker/share/x.db`) | **[Likely]** - mechanism publicly documented; **not tested**, no capture tooling built | - |
| 6 | **Full remote-DBMS outbound exfiltration channel** (credentials embedded in the URL arrive at the attacker host) | **[Likely]** - completes only where an async driver (asyncpg/aiomysql) is installed; the audited environment stopped at driver load for the *socket* test, while effect 3 shows the destination is attacker-chosen | - |
| 7 | **DoS** - URL pointed at a locked / unwritable / huge path blocks or errors the storage path; `create_all`/Alembic on a foreign database | **[Likely]** | - |

![Attack request](screenshots/03-attack-request-real-rest-api.png)

*Figure 4 - the attack result against the unmodified service: the DB file at
the attacker-chosen path was created through the real REST API. No `/fuzz/probe`,
no modified build.*

![Full run](screenshots/05-full-run-output-real-api.png)

*Figure 5 - full transcript of the real-deployment run: section A (file
created at the attacker path, `POST /credential` -> `201`), section B
(startup bytes received at the attacker listener), and the verdicts.*

![Key evidence](screenshots/06-key-evidence-real-deploy.png)

*Figure 6 - key evidence lines of the real-deployment run:
`ARBITRARY_DB_PATH_FILE_CREATE = True`,
`OUTBOUND_CONNECT_TO_ATTACKER_HOST = True`,
`SQL_REACHES_ATTACKER_CONNECTION = False` (stated honestly - the captured
payload was the startup packet only; the fixed PRAGMA rides the SQLite path),
`EXP_SUCCESS = True`.*

## Impact

**With URL influence (the documented configuration surface):**

- **File-system primitive outside the data directory.** The service creates
  (or opens) a SQLite database wherever the URL says - world-writable
  locations, scheduled-task directories, or an existing attacker-prepared
  database file. Opening an attacker-**pre-provisioned** DB file is worse than
  creating an empty one: the Agent Service then reads its session/credential
  state from tables the attacker authored, i.e. application-state injection.
- **SQL execution on an attacker-selected target.** The connect callback's
  statement, and by default `Base.metadata.create_all`, run against the
  attacker's file or server. The fixed text bounds the immediate damage, but
  the *placement* of execution is the vulnerability: it is a code-execution
  surface pointed wherever the configuration string points.
- **Outbound to attacker infrastructure.** With a remote dialect the engine
  dials the host:port the URL names; the URL's embedded credentials arrive in
  the startup packet, and the connection itself is an SSRF-class egress from
  the server (effect 3 measured; full DBMS handshake completion is `[Likely]`
  and driver-dependent, effect 6).
- **On Windows, `[Likely]` credential theft.** A UNC path in a SQLite URL
  (`////host/share/x.db`) triggers SMB authentication from the service
  account, leaking a NetNTLM hash to the attacker's host for offline cracking
  or relay. This mechanism is publicly documented; we did not build capture
  tooling and state it as `[Likely]`, not as tested fact.

Confidentiality is Low in the measured tier (no secret read in our runs; the
pre-provisioned-file and NTLM paths raise it to H), integrity is Low (files
created, schema written to chosen targets), availability is Low (a bad target
stalls or breaks the storage path). `S:C` because the file creation and the
outbound connection leave the component's security scope into the attacker's.

## Reproduction

### A. Self-contained (no AgentScope install needed) - start here

`poc/exp_storage_sql.py` re-executes the vulnerable control flow exactly as it
appears in `_storage.py` - the same scheme-to-dialect decision, the same
connect-callback `PRAGMA`, the same unvalidated path - using only the Python
standard library, so a reviewer can confirm the behaviour with one command:

```bash
python poc/exp_storage_sql.py
```

Expected output (verbatim from a fresh run on this repository; full transcript
in [`evidence/exp_storage_sql.log`](evidence/exp_storage_sql.log)):

```text
[A] file present before connect          = False
[A][attacker-view] file present after connect  = True (12288 bytes)
[B] SQL captured by the connection trace:
        'PRAGMA foreign_keys=ON'
        'CREATE TABLE IF NOT EXISTS credential (id TEXT PRIMARY KEY, data TEXT)'
        'PRAGMA foreign_keys'
[B] PRAGMA foreign_keys read back (same conn)  = 1 (=1 proves it executed)
...
[VERDICT] ARBITRARY_DB_FILE_CREATE      = True (CWE-73, section A)
[VERDICT] SQL_EXEC_ON_ATTACKER_CONNECTION = True (PRAGMA traced + read back =1, section B)
[VERDICT] ARBITRARY_SCHEME_ACCEPTED     = True (URL->engine decides destination, section C)
[VERDICT] EXP_SUCCESS = True
```

The script uses stdlib `sqlite3` as the DB-API driver instead of `aiosqlite`;
the defect lives in *how the URL is trusted and where the callback fires*,
which is identical either way. If SQLAlchemy + aiosqlite are installed,
`--with-sqlalchemy` additionally runs the same effect through the real
`create_async_engine` path.

![Function PoC](screenshots/08-func-poc-sql-trace-evidence.png)

*Figure 7 - the function-level evidence from the original audit run: the
captured statement list including `PRAGMA foreign_keys=ON`, the pragma read
back as `1`, and the three verdicts.*

### B. Against an unmodified AgentScope Agent Service

```bash
pip install "agentscope[full]"        # tested: 2.0.11

# terminal 1 - unmodified service; storage URL supplied via REAL_DB_URL
REAL_DB_URL="sqlite+aiosqlite:///C:/Windows/Tmp/attacker.db" python poc/deploy_real.py

# terminal 2 - orchestrator: attacker-path run + asyncpg listener run + restore
python poc/exp_real_api.py
```

`exp_real_api.py` stops the service on `:8000`, restarts it twice with
attacker-chosen storage URLs (a SQLite path in `%TEMP%`, then
`postgresql+asyncpg://exfil:***@127.0.0.1:18847/db` with a fake-PostgreSQL
listener), drives real REST traffic (`POST /credential/`), asserts the
attacker-side observations, and finally restores the default service. It uses
only the documented assembly point (`AsyncSQLAlchemyStorage` passed to
`create_app`) and documented constructor parameters - it does not patch,
monkey-patch or instrument the product. `deploy_real.py` prints the storage
parameter names it found on the installed build because those names move
across 2.0.x releases; adjust one line if your build differs.

The original audit transcript is
[`evidence/exp_real_api.log`](evidence/exp_real_api.log) (matches Figures
4-6).

### C. Scoring

```bash
python poc/cvss_calc.py
```

Prints the four vectors below, computed with the FIRST v3.1 formula.

## CVSS

| Scenario | Vector | Score |
|---|---|---|
| **Recommended: measured effects only** (file creation + SQL on attacker connection + arbitrary scheme accepted) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L` | **7.4 High** |
| With UNC -> NetNTLM capture accepted (`[Likely]`, not tested) | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L` | 9.1 Critical |
| Multi-tenant URL passed straight from an end user (`PR:N`) | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L` | 9.9 Critical |
| File creation + outbound, both counted at `I:H` | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L` | 9.9 Critical |

![CVSS](screenshots/09-cvss-rating.png)

*Figure 8 - the CVSS table from the audit report.*

Rationale for the recommended row: `AV:N/AC:L` - the service is a network
backend and the callback is registered unconditionally; `PR:L` - the storage
URL is normally deployment/tenant configuration, needing some privilege but
not admin; `UI:N`; `S:C` - the created file and the outbound connection leave
the component's scope; `C:L/I:L/A:L` - bounded to what was actually measured.
State 7.4 High for the measured case; use 9.1 only where you accept the UNC
mechanism and say so explicitly.

## Why this is not intended behaviour

- **The URL is documented as the input, not as a trusted-config boundary.**
  The docstring's own examples are an arbitrary relative file path and an
  arbitrary remote host. A component whose *purpose* is to accept a connection
  string still has to decide whether that string is trusted input; here the
  question is never asked - there is no scheme allow-list, no path constraint,
  no host check, no warning.
- **The callback fires on whatever connection the string produced.** Enabling
  foreign keys is a reasonable goal; executing SQL on an unvalidated,
  attacker-selectable target is not. The same event registration also runs
  `create_all` (default on) and Alembic migrations against that target.
- **File creation outside the data directory is a security-relevant side
  effect of "opening the database".** Ordinary practice for embedded
  databases is to resolve the path and constrain it to a known root; `L156`
  stores the raw string and `L180` consumes it.
- **The generality arguments (G1-G5) hold:** no switch exists to turn the
  behaviour off (G1); every channel that can set the URL reaches the same
  sink (G2); the code path is pure storage initialization, independent of any
  business trigger (G3); single-node, multi-tenant and self-hosted deployments
  across SQLite/PostgreSQL/MySQL dialects share the one entry point (G4); and
  even restricting the scheme would not help, because the path inside the URL
  is still used verbatim - the root cause is trusting the URL, not the scheme
  parser (G5).

## Remediation

**P0 - validate the URL before it reaches the engine.**

```python
# FIX: scheme allow-list + path constrained to the app data dir + reject UNC
u = sqlalchemy.engine.url.make_url(url)
if u.drivername not in {"sqlite+aiosqlite"}:      # or an explicit operator list
    raise ValueError(f"storage driver not allowed: {u.drivername}")
p = pathlib.Path(u.database or "").resolve()
if not p.is_relative_to(APP_DATA_DIR):
    raise ValueError("storage path outside the application data directory")
# reject UNC outright on Windows: str(p).startswith("\\\\")
```

For multi-tenant deployments: never accept a connection string from a
lower-privileged party - derive a controlled path from the tenant ID
server-side. If remote databases are supported, take the URL only from
operator configuration (env / secret store), never from request data, and
route egress through an audited proxy.

![Fix skeleton](screenshots/07-fix-skeleton.png)

*Figure 9 - the P0 fix skeleton as prepared for the vendor: scheme allow-list,
`resolve()` + `is_relative_to(APP_DATA_DIR)` path constraint, UNC rejection.*

**P1 - narrow what the connect callback and defaults do.** Gate
`PRAGMA foreign_keys=ON` behind the same validated, allow-listed configuration
(it is also achievable via SQLAlchemy pool events on vetted engines); default
`create_tables` to `False` and keep schema creation in an explicit migration
step; filter SQLite URL query parameters that change driver behaviour
(`?uri=true` and friends).

**P2 - defence in depth.** Audit-log every storage-path resolution and every
outbound DB connection with the resolved destination; on Windows deployments
disable SMB name-resolution for service accounts or block UNC in policy;
add a regression test that a URL outside the data directory is rejected.

**Workaround for operators today.** Build `AsyncSQLAlchemyStorage` yourself
from a URL your deployment owns (never from tenant/user data), pin it to a
path under a directory only the service writes to, and treat any configuration
surface that lets a lower-privileged party set the storage URL - admin form,
tenant record, environment override - as privileged.

## Verification status

| Item | Status |
|---|---|
| Sink and taint chain read from source at 2.0.11 | **Verified** (Figures 1-2) |
| Arbitrary-path DB file creation via real REST (`POST /credential/` -> `201`) | **Verified** (Figures 4-6, `evidence/exp_real_api.log`) |
| `PRAGMA foreign_keys=ON` executed on the attacker-selected connection (trace + read back `=1`) | **Verified** (Figure 7, `evidence/exp_storage_sql.log`) |
| `postgresql+asyncpg` URL parsed to the postgres dialect; attacker listener received the startup packet | **Verified** (Figures 5-6) |
| `create_all` statement traced against the chosen target | **Verified** (self-contained run) |
| Self-contained reproduction without AgentScope installed | **Verified** (fresh run, `evidence/exp_storage_sql.log`) |
| UNC -> NetNTLM credential capture | **Not tested** - `[Likely]` mechanism; do not state as fact |
| Full remote-DBMS outbound completion | **Driver-dependent** - audited env had no asyncpg driver; destination selection itself is verified |
| `2.0.12` / `main` still affected | **Not tested** - re-verify before filing |
| Vendor notified | **No** |

Only the rows marked **Verified** should be stated as tested fact in a CVE
description. The `[Likely]` and "not tested" rows must stay hedged.

## Disclosure

All testing was performed on self-owned machines and loopback addresses: the
"attacker path" was a `%TEMP%` directory on the test host, the "attacker
PostgreSQL host" was a capture socket bound to `127.0.0.1:18847`, and the
credentials in the URLs were dummy values. No third-party system was touched,
no credential-capture tooling was built, and no NetNTLM hashes were collected.

## Timeline

| Date | Event |
|---|---|
| 2026-10-27 | AgentScope 2.0.11 published on PyPI (the audited version) |
| 2026-11-16 | Code audit; effects reproduced against an unmodified local Agent Service (real-deployment run, `evidence/exp_real_api.log`) |
| 2026-11-18 | Self-contained reproduction (`poc/exp_storage_sql.py`) re-run on this repository; fresh transcript at `evidence/exp_storage_sql.log`; advisory drafted here |
| 2026-11-18 | **No CVE ID requested yet; vendor not yet contacted** |

## References

- AgentScope repository - https://github.com/agentscope-ai/agentscope
- AgentScope on PyPI (2.0.11 released 2026-10-27) - https://pypi.org/project/agentscope/
- AgentScope documentation - https://docs.agentscope.io/
- SQLAlchemy `create_async_engine` - https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- CWE-73 External Control of File Name or Path - https://cwe.mitre.org/data/definitions/73.html
- CWE-918 Server-Side Request Forgery - https://cwe.mitre.org/data/definitions/918.html
- CVSS v3.1 specification - https://www.first.org/cvss/specification-document

## Credits

Discovered, audited and reported by **gaoxihan** (<https://github.com/taalsa>).
