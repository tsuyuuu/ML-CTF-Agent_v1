#!/usr/bin/env python3
"""
Probe an HTB CTF event over MCP (read-only): teams, event details, challenge
list, and a download link for the first challenge. Shows us the exact field
names so we can finish the runner.

    export HTB_TOKEN=<your HTB MCP token>
    python3 htb_explore.py            # defaults to CTF Try Out (1434)
    HTB_EVENT_ID=1434 python3 htb_explore.py
"""
import json
import os
import sys

from htb_mcp import HTBClient

EVENT = int(os.environ.get("HTB_EVENT_ID", "1434"))


def show(label, obj, n=3500):
    print(f"\n=== {label} ===")
    try:
        print(json.dumps(obj, indent=2)[:n])
    except Exception:
        print(repr(obj)[:n])


def main():
    token = os.environ.get("HTB_TOKEN")
    if not token:
        sys.exit("set HTB_TOKEN")
    c = HTBClient(token)

    try:
        show("retrieve_my_teams", c.retrieve_my_teams(), 1500)
    except Exception as e:
        print("retrieve_my_teams error:", e)

    try:
        ctf = c.retrieve_ctf(EVENT)
    except Exception as e:
        print(f"\nretrieve_ctf({EVENT}) error:", e)
        print("If this is a permission/no_mcp error, the event just isn't "
              "MCP-playable — the connection itself is still proven.")
        return

    if isinstance(ctf, dict):
        print(f"\nretrieve_ctf({EVENT}) top-level keys:", list(ctf.keys()))
    show(f"retrieve_ctf({EVENT})", ctf)

    # Find the challenge list wherever it lives.
    challenges = None
    if isinstance(ctf, dict):
        for k in ("challenges", "challenge", "data", "ctf_challenges"):
            v = ctf.get(k)
            if isinstance(v, list):
                challenges = v
                break
    if not challenges:
        print("\n(no challenge list at a known key — inspect the JSON above and "
              "tell me which key holds the challenges)")
        return

    print(f"\n=== {len(challenges)} challenges ===")
    for ch in challenges[:25]:
        if isinstance(ch, dict):
            print("  " + json.dumps({k: ch.get(k) for k in (
                "id", "name", "category", "challenge_category", "points",
                "solved", "hasDownload", "filename", "download",
                "hasDocker", "docker", "container", "difficulty",
            ) if k in ch}))

    first = challenges[0] if isinstance(challenges[0], dict) else {}
    cid = first.get("id")
    if cid:
        try:
            show(f"get_download_link(challenge_id={cid})",
                 c.get_download_link(cid), 1200)
        except Exception as e:
            print(f"\nget_download_link({cid}) error:", e,
                  "\n(expected if the event is no_mcp — real event tomorrow will allow it)")


if __name__ == "__main__":
    main()
