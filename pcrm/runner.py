"""RunManager — run one collection at a time in the background, with live status.

The GUI triggers a run and polls `status()` for progress; only one run may be in
flight (a single-run lock). Secrets are injected into the environment for the
run's duration. Each run is recorded as a row in the `runs` table.
"""

from __future__ import annotations

import threading

from . import pipeline
from .models import utcnow_iso
from .secrets import SecretStore, injected_env
from .store import Store, db_path


class RunInProgress(Exception):
    """Raised by start() when a collection is already running."""


def _idle_status() -> dict:
    return {"state": "idle", "run_id": None, "collectors": [], "phase": None,
            "summary": None, "error": None, "started_at": None, "finished_at": None}


class RunManager:
    def __init__(self, data_root: str = "data", secret_store: SecretStore | None = None):
        self.data_root = data_root
        self.secret_store = secret_store or SecretStore()
        self._run_lock = threading.Lock()      # held for the lifetime of a run
        self._status_lock = threading.Lock()   # guards _status
        self._status = _idle_status()
        self._thread: threading.Thread | None = None

    # ----------------------------------------------------------- status
    def status(self) -> dict:
        with self._status_lock:
            s = dict(self._status)
            s["collectors"] = list(self._status["collectors"])
            return s

    def is_running(self) -> bool:
        with self._status_lock:
            return self._status["state"] == "running"

    # ----------------------------------------------------------- control
    def start(self, *, trigger: str = "manual", inject_secrets: bool = True,
              **run_kwargs) -> int:
        """Begin a run in a worker thread; returns its run_id. Raises
        RunInProgress if one is already running."""
        if not self._run_lock.acquire(blocking=False):
            raise RunInProgress("a collection is already running")
        try:
            store = Store(db_path(self.data_root))
            run_id = store.start_run(trigger=trigger)
            store.close()
            with self._status_lock:
                self._status = _idle_status()
                self._status.update(state="running", run_id=run_id,
                                    started_at=utcnow_iso())
            self._thread = threading.Thread(
                target=self._worker, args=(run_id, inject_secrets, run_kwargs),
                name=f"ssp-run-{run_id}", daemon=True)
            self._thread.start()
            return run_id
        except BaseException:
            self._run_lock.release()
            raise

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    # ----------------------------------------------------------- internal
    def _on_event(self, ev: dict) -> None:
        with self._status_lock:
            t = ev.get("type")
            if t == "collector":
                self._status["collectors"].append(
                    {k: v for k, v in ev.items() if k != "type"})
            elif t == "phase":
                self._status["phase"] = ev.get("name")
            elif t == "run_done":
                self._status["summary"] = ev.get("summary")

    def _worker(self, run_id: int, inject_secrets: bool, run_kwargs: dict) -> None:
        status, summary, error = "done", None, None
        run_kwargs.setdefault("data_root", self.data_root)
        try:
            if inject_secrets:
                with injected_env(self.secret_store):
                    summary = pipeline.run(on_event=self._on_event, **run_kwargs)
            else:
                summary = pipeline.run(on_event=self._on_event, **run_kwargs)
        except BaseException as e:  # noqa: BLE001 - record the failure on the run
            status, error = "failed", str(e)
        finally:
            collectors = self.status()["collectors"]
            store = Store(db_path(self.data_root))
            store.finish_run(run_id, status, summary, collectors)
            store.close()
            with self._status_lock:
                self._status.update(state=status, finished_at=utcnow_iso(),
                                    summary=summary, error=error)
            self._run_lock.release()
