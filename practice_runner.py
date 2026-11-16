"""Independent CTFTiny practice runner; does not touch submitted evaluation results.

Requires existing benchmark_runner.py with run_trial/preflight; expects the trusted
controller to retain answer metadata and the agent to use only staged contestant files.
"""
import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from benchmark_runner import preflight, run_trial

ROOT = Path(__file__).resolve().parent
PRACTICE_IDS = ROOT / "practice_ids.txt"
RESULTS = ROOT / "results" / "practice" / "attempts.jsonl"
TOOLS = ROOT / "tools.json"


def load_ids():
    ids = [line.strip() for line in PRACTICE_IDS.read_text().splitlines()
           if line.strip() and not line.lstrip().startswith("#")]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate practice IDs")
    return ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="Show challenge roster")
    parser.add_argument("--check", action="store_true", help="Preflight without model calls")
    parser.add_argument("--challenge-id", help="Run one selected challenge")
    args = parser.parse_args()

    ids = load_ids()
    if args.list:
        print("\n".join(ids))
        return
    if not args.challenge_id:
        parser.error("--challenge-id required for --check or run (no bulk runs)")
    if args.challenge_id not in ids:
        parser.error("ID not in practice_ids.txt")

    try:
        challenge = preflight(args.challenge_id)
    except (ValueError, TypeError, FileNotFoundError) as exc:
        print(f"NOT READY: {args.challenge_id}: {exc}")
        print("Do not work around service restrictions; service targets require a reviewed launcher.")
        raise SystemExit(2)
    print(f"READY: {args.challenge_id} ({challenge.category}; files={challenge.files})", flush=True)
    if args.check:
        print("Preflight complete. No API calls or flags used.")
        return

    api_key = os.getenv("OLLAMA_API_KEY")
    if not api_key:
        parser.error("OLLAMA_API_KEY is missing; configure Codespaces secret and restart")

    tools = json.loads(TOOLS.read_text(encoding="utf-8"))
    result = run_trial(args.challenge_id, 1, "practice", tools, api_key)
    result["practice_timestamp"] = datetime.now(timezone.utc).isoformat()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(result) + "\n")
    print("\n=== PRACTICE RESULT ===", flush=True)
    print(json.dumps(result, indent=2), flush=True)
    print(f"Saved to {RESULTS}")


if __name__ == "__main__":
    main()
