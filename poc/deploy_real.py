# -*- coding: utf-8 -*-
"""Deploy an UNMODIFIED AgentScope Agent Service with the documented GitHubMCPHub
assembly, so that `exp_real_api.py` can reach the sink through the product's own
REST API (no test-only endpoint, no patched code).

Environment:
    REAL_PORT         listen port                     (default 8001)
    REAL_HUB_BASE     GitHubMCPHub(base_url=...)      (default official registry)
    REAL_HUB_TOKEN    GitHubMCPHub(api_token=...)     (optional; the canary)
    REAL_DB_URL       storage URL                     (default sqlite+aiosqlite)

    python deploy_real.py

Requires: pip install "agentscope[service]"   (tested against 2.0.11)
`GitHubMCPHub` and the `mcp_hubs` assembly argument are documented at
https://docs.agentscope.io/latest/en/deploy/hub/mcp-hub
"""
import inspect
import os
import sys


def build_hub():
    from agentscope.app.hub import GitHubMCPHub

    base = os.environ.get("REAL_HUB_BASE") or "https://api.mcp.github.com"
    token = os.environ.get("REAL_HUB_TOKEN") or None
    print("[deploy] GitHubMCPHub(base_url=%r, api_token=%s)"
          % (base, "<set>" if token else None))
    return GitHubMCPHub(base_url=base, api_token=token)


def main():
    try:
        from agentscope.app import create_app
    except ImportError as e:
        print("[ERR] cannot import agentscope.app.create_app: %s" % e)
        print("      pip install 'agentscope[full]' and retry.")
        return 2

    hub = build_hub()
    port = int(os.environ.get("REAL_PORT", "8001"))
    params = inspect.signature(create_app).parameters
    print("[deploy] create_app parameters: %s" % list(params))

    kwargs = {}
    # The hub list argument is named `mcp_hubs` in the 2.0.x documentation.
    for name in ("mcp_hubs", "hubs", "mcp_hub_list"):
        if name in params:
            kwargs[name] = [hub]
            print("[deploy] create_app(%s=[GitHubMCPHub])" % name)
            break
    else:
        print("[WARN] no hub argument found on create_app; parameters are: %s"
              % list(params))
        print("       Adjust this script to the assembly point of your build.")

    if "storage_url" in params and os.environ.get("REAL_DB_URL"):
        kwargs["storage_url"] = os.environ["REAL_DB_URL"]

    app = create_app(**kwargs)

    try:
        import uvicorn
    except ImportError:
        print("[ERR] pip install uvicorn")
        return 2
    print("[deploy] serving unmodified Agent Service on 127.0.0.1:%d" % port)
    uvicorn.run(app, host="127.0.0.1", port=port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
