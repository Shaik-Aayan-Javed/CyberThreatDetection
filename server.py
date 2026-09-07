"""Dashboard backend: replay control, live alert stream, statistics.

    python server.py                 then open http://127.0.0.1:8000

Direction of data matters here. This process reads capture files and pushes
alerts *outward* to a browser inside the monitoring enclave. Nothing it does
reaches back toward the monitored network -- the detection path itself
(ingest/, features/, detectors/) contains no networking code at all, which
tools/isolation_check.py verifies mechanically.

The engine runs on a worker thread and hands alerts to the event loop through a
plain queue, so a slow or disconnected browser can never stall detection. If the
dashboard falls behind, it loses view updates, not alerts -- every alert is
retained in the ring buffer and in the JSONL file on disk.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import queue
import threading
from collections import deque
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

import config
import engine
from alerts.schema import Alert

config.load_env()

PCAP_DIR = config.pcap_dir()
DASHBOARD = config.dashboard()
ALERT_LOG = config.alert_log()
MAX_ALERTS = config.max_alerts()


class Hub:
    """Fan-out of engine events to every connected dashboard."""

    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()
        self.events: queue.Queue = queue.Queue()
        self.alerts: deque = deque(maxlen=MAX_ALERTS)
        self.stats: dict[str, Any] = {}
        self.replay: dict[str, Any] = {"running": False, "capture": None, "speed": 0}
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()

    # -- called from the engine worker thread --------------------------------
    def on_alert(self, alert: Alert) -> None:
        payload = alert.to_dict()
        self.alerts.appendleft(payload)
        with open(ALERT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
        self.events.put({"type": "alert", "data": payload})

    def on_window(self, stats: engine.EngineStats) -> None:
        self.stats = stats.to_dict()
        self.stats["replay"] = dict(self.replay)
        self.events.put({"type": "stats", "data": self.stats})

    # -- called from the event loop ------------------------------------------
    async def broadcast(self, message: dict) -> None:
        if not self.clients:
            return
        text = json.dumps(message)
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    async def pump(self) -> None:
        """Drain the worker's queue into connected sockets."""
        while True:
            drained = 0
            while drained < 200:
                try:
                    message = self.events.get_nowait()
                except queue.Empty:
                    break
                await self.broadcast(message)
                drained += 1
            await asyncio.sleep(0.05)

    def start_replay(self, capture: str, speed: float, window: float, use_model: bool) -> dict:
        if self.replay["running"]:
            return {"ok": False, "error": "a replay is already running"}

        path = os.path.join(PCAP_DIR, capture)
        if not os.path.exists(path):
            return {"ok": False, "error": f"no such capture: {capture}"}

        self.alerts.clear()
        self.stop_flag.clear()
        self.replay = {"running": True, "capture": capture, "speed": speed}

        def work() -> None:
            try:
                stats = engine.run(
                    path,
                    speed=speed,
                    window_s=window,
                    model_path=engine.DEFAULT_MODEL_PATH if use_model else None,
                    enable_anomaly=use_model,
                    on_alert=self.on_alert,
                    on_window=self.on_window,
                )
                self.stats = stats.to_dict()
            except Exception as exc:  # surface failures in the UI, not just the log
                self.events.put({"type": "error", "data": {"message": str(exc)}})
            finally:
                self.replay = {"running": False, "capture": capture, "speed": speed}
                self.stats["replay"] = dict(self.replay)
                self.events.put({"type": "done", "data": self.stats})

        self.worker = threading.Thread(target=work, name="engine", daemon=True)
        self.worker.start()
        return {"ok": True, "capture": capture, "speed": speed}


hub = Hub()


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(hub.pump())
    yield
    task.cancel()


app = FastAPI(title="SIH26145 Unidirectional Threat Monitor", lifespan=lifespan)


@app.get("/")
async def index():
    return FileResponse(DASHBOARD)


@app.get("/api/captures")
async def captures():
    if not os.path.isdir(PCAP_DIR):
        return JSONResponse({"captures": []})
    items = []
    for name in sorted(os.listdir(PCAP_DIR)):
        if name.endswith((".pcap", ".pcapng")):
            items.append({"name": name, "bytes": os.path.getsize(os.path.join(PCAP_DIR, name))})
    return JSONResponse({"captures": items, "model_trained": os.path.exists("models/anomaly.joblib")})


@app.get("/api/alerts")
async def get_alerts():
    return JSONResponse({"alerts": list(hub.alerts), "stats": hub.stats})


@app.get("/api/stats")
async def get_stats():
    return JSONResponse(hub.stats or {"packets": 0, "alerts": 0})


@app.post("/api/replay")
async def start_replay(body: dict):
    return JSONResponse(
        hub.start_replay(
            capture=body.get("capture", "mixed.pcap"),
            speed=float(body.get("speed", config.replay_speed())),
            window=float(body.get("window", config.window_s())),
            use_model=bool(body.get("model", True)),
        )
    )


@app.websocket("/stream")
async def stream(ws: WebSocket):
    await ws.accept()
    hub.clients.add(ws)
    try:
        await ws.send_text(json.dumps({
            "type": "snapshot",
            "data": {"alerts": list(hub.alerts), "stats": hub.stats},
        }))
        while True:
            # The dashboard is display-only; inbound frames are just keepalives.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        hub.clients.discard(ws)


def main() -> int:
    ap = argparse.ArgumentParser(description="SIH26145 dashboard server")
    ap.add_argument("--host", default=config.host(),
                    help="bind address; defaults to loopback (enclave-internal). "
                         "Overrides SIH_HOST from .env")
    ap.add_argument("--port", type=int, default=config.port(),
                    help="overrides SIH_PORT from .env")
    args = ap.parse_args()

    os.makedirs("data", exist_ok=True)
    import uvicorn

    print(f"Dashboard: http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
