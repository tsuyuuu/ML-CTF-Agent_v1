#!/usr/bin/env python3
"""
HTB CTF MCP client — dependency-light (uses only `requests`).

Speaks the MCP streamable-HTTP JSON-RPC protocol directly, so it does NOT depend
on the `mcp` SDK (whose API keeps shifting across versions). Connects your agent
to Hack The Box's CTF event MCP server.

Server:  https://mcp.hackthebox.ai/v1/ctf/mcp/   (streamable-HTTP, Bearer token)
Token:   personal MCP token from HTB Profile Settings -> MCP Access

FIRST: run it standalone to confirm the connection and DUMP the real tools:

    export HTB_TOKEN=<your personal HTB MCP token>
    python3 htb_mcp.py

Paste the printed tool dump back and we wire the exact names/params into the
runner. The convenience methods guess tool names by keyword so they keep working
across small naming differences; we confirm against the dump.
"""
import json
import os
import sys

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: python3 -m pip install requests")

HTB_MCP_URL = os.environ.get("HTB_MCP_URL", "https://mcp.hackthebox.ai/v1/ctf/mcp/")


class HTBClient:
    """Minimal synchronous MCP streamable-HTTP client for the HTB CTF server."""

    def __init__(self, token, url=HTB_MCP_URL):
        self.url = url
        self.token = token
        self.session_id = None
        self.protocol_version = "2025-06-18"
        self._init_done = False
        self._id = 0
        self.tools = []
        self._initialize()

    # --- transport -----------------------------------------------------------
    def _headers(self):
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self.token}",
        }
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if self._init_done and self.protocol_version:
            h["MCP-Protocol-Version"] = self.protocol_version
        return h

    def _request(self, method, params=None, is_notification=False):
        self._id += 1
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        target_id = None
        if not is_notification:
            payload["id"] = self._id
            target_id = self._id

        resp = requests.post(self.url, headers=self._headers(),
                             json=payload, timeout=(10, 180), stream=True)
        resp.raise_for_status()

        sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
        if sid:
            self.session_id = sid

        if is_notification:
            resp.close()
            return None

        ctype = resp.headers.get("Content-Type", "")
        try:
            if "text/event-stream" in ctype:
                for raw in resp.iter_lines(decode_unicode=True):
                    if not raw:
                        continue
                    raw = raw.strip()
                    if raw.startswith("data:"):
                        data = raw[5:].strip()
                        if not data:
                            continue
                        try:
                            m = json.loads(data)
                        except Exception:
                            continue
                        if m.get("id") == target_id:
                            if "error" in m:
                                raise RuntimeError(f"MCP error: {m['error']}")
                            return m.get("result")
                return None
            else:
                body = resp.json()
                msgs = body if isinstance(body, list) else [body]
                for m in msgs:
                    if m.get("id") == target_id:
                        if "error" in m:
                            raise RuntimeError(f"MCP error: {m['error']}")
                        return m.get("result")
                return None
        finally:
            resp.close()

    def _initialize(self):
        result = self._request("initialize", {
            "protocolVersion": self.protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "htb-ctf-agent", "version": "1.0"},
        }) or {}
        # Adopt the server's negotiated protocol version if it gave one.
        if result.get("protocolVersion"):
            self.protocol_version = result["protocolVersion"]
        self._init_done = True
        self._request("notifications/initialized", is_notification=True)
        tl = self._request("tools/list", {}) or {}
        self.tools = tl.get("tools", [])

    # --- public API ----------------------------------------------------------
    def tool_name(self, *keywords):
        for t in self.tools:
            n = t.get("name", "").lower()
            if all(k in n for k in keywords):
                return t["name"]
        return None

    def call(self, name, **args):
        if name is None:
            raise RuntimeError("tool not found on server; check the tool dump")
        result = self._request("tools/call", {"name": name, "arguments": args}) or {}
        parts = [c.get("text", "") for c in result.get("content", [])
                 if c.get("type") == "text"]
        text = "\n".join(parts)
        if not text:
            return result
        try:
            return json.loads(text)
        except Exception:
            return text

    # --- exact HTB CTF MCP methods (confirmed from the live tool dump) --------
    def list_events(self):
        return self.call("list_ctf_events")

    def retrieve_ctf(self, ctf_id):
        """Event details + the user's participation + the event's challenges."""
        return self.call("retrieve_ctf", ctf_id=ctf_id)

    def retrieve_my_teams(self):
        return self.call("retrieve_my_teams")

    def join_ctf_event(self, ctf_id, team_id, consent=True, ctf_password=None):
        return self.call("join_ctf_event", ctf_id=ctf_id, team_id=team_id,
                         consent=consent, ctf_password=ctf_password)

    def get_download_link(self, challenge_id):
        """Temporary signed URL (valid 5 min) to download a challenge's files."""
        return self.call("get_download_link", challenge_id=challenge_id)

    def start_container(self, challenge_id):
        return self.call("start_container", challenge_id=challenge_id)

    def container_status(self, challenge_id):
        return self.call("container_status", challenge_id=challenge_id)

    def stop_container(self, challenge_id):
        return self.call("stop_container", challenge_id=challenge_id)

    def submit_flag(self, challenge_id, flag):
        return self.call("submit_flag", challenge_id=challenge_id, flag=flag)

    def retrieve_ctf_scores(self, ctf_id):
        return self.call("retrieve_ctf_scores", ctf_id=ctf_id)


def _dump(c):
    print(f"Connected to {c.url}")
    print(f"protocol={c.protocol_version} session={c.session_id}")
    print(f"{len(c.tools)} tools:\n")
    for t in c.tools:
        print(f"== {t.get('name')}")
        d = t.get("description") or ""
        if d:
            print(f"   desc:  {d[:140]}")
        try:
            print(f"   input: {json.dumps(t.get('inputSchema', {}))[:500]}")
        except Exception:
            pass
        print()


if __name__ == "__main__":
    token = os.environ.get("HTB_TOKEN")
    if not token:
        sys.exit("set HTB_TOKEN to your personal HTB MCP token "
                 "(HTB Profile Settings -> MCP Access)")
    c = HTBClient(token)
    _dump(c)
    print("--- trying list_ctf_events ---")
    try:
        print(json.dumps(c.list_events(), indent=2)[:3000])
    except Exception as e:
        print("list_events failed (adjust name/args from the dump above):", e)
