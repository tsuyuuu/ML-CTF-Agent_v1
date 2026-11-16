"""Trusted-controller configuration; never derive limits from model output."""
import os


def limits_from_env():
    """Keep old defaults while permitting bounded development experiments.

    Caps are engineering safeguards, not assertions about competition rules.
    """
    try:
        steps = int(os.environ.get("CTF_MAX_STEPS", "15"))
        seconds = int(os.environ.get("CTF_MAX_SECONDS", "300"))
    except ValueError as exc:
        raise ValueError("CTF limits must be integers") from exc
    if not 1 <= steps <= 100:
        raise ValueError("CTF_MAX_STEPS must be between 1 and 100")
    if not 30 <= seconds <= 3600:
        raise ValueError("CTF_MAX_SECONDS must be between 30 and 3600")
    return steps, seconds
