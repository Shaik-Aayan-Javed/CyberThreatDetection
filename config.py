"""Runtime configuration for the dashboard service.

There are no secrets in this project. It reads capture files off disk and talks
to nobody -- there is no API key, no token, no database credential and no
account to authenticate against. `.env` here holds *deployment settings* (bind
address, paths, tuning), which is a different thing from a secrets file, and
`.env.example` documents them.

Deliberately NOT imported by the detection path. `engine.py` and everything
under ingest/ features/ detectors/ alerts/ take their settings from CLI flags
and open exactly one file: the capture. Reading an environment file there would
put a second descriptor into a code path whose entire claim is that it opens
one, and tools/isolation_check.py layer 3 would have to be weakened to allow it.

So the split is: **CLI flags configure the analyser, environment configures the
service.** `python engine.py --window 10` still works exactly as before and is
unaffected by anything in this file.
"""

from __future__ import annotations

import os

ENV_FILE = ".env"


def load_env(path: str = ENV_FILE) -> int:
    """Fold a .env file into os.environ. Returns how many keys were set.

    Deliberately tiny and dependency-free -- python-dotenv would be a new
    install for `KEY=value` parsing. Existing environment variables win, so an
    explicit `set SIH_PORT=9000` overrides the file rather than the reverse.
    """
    if not os.path.exists(path):
        return 0

    applied = 0
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            # Tolerate quoted values; nothing here needs them, but a path with
            # a space would otherwise silently break.
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key and key not in os.environ:
                os.environ[key] = value
                applied += 1
    return applied


def _str(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


# --- service --------------------------------------------------------------
def host() -> str:
    """Bind address. Loopback by default: the safe option is the lazy one."""
    return _str("SIH_HOST", "127.0.0.1")


def port() -> int:
    return _int("SIH_PORT", 8000)


# --- paths ----------------------------------------------------------------
def pcap_dir() -> str:
    return _str("SIH_PCAP_DIR", os.path.join("data", "pcaps"))


def dashboard() -> str:
    return _str("SIH_DASHBOARD", os.path.join("dashboard", "index.html"))


def alert_log() -> str:
    return _str("SIH_ALERT_LOG", os.path.join("data", "alerts.jsonl"))


def model_path() -> str:
    return _str("SIH_MODEL_PATH", os.path.join("models", "anomaly.joblib"))


# --- tuning ---------------------------------------------------------------
def max_alerts() -> int:
    """Ring-buffer depth held in memory for the dashboard."""
    return _int("SIH_MAX_ALERTS", 500)


def window_s() -> float:
    return _float("SIH_WINDOW_S", 5.0)


def replay_speed() -> float:
    """Default replay pacing: 0 = as fast as possible, 1 = wall-clock."""
    return _float("SIH_REPLAY_SPEED", 20.0)
