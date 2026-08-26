"""Read-only FastAPI service for deterministic mutation artifacts."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Callable

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from hardening_game.mutations.explorer import (
    UnknownMutationCandidate,
    list_mutation_runs,
    load_mutation_record_detail,
    load_mutation_run_index,
)


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def create_app(project_root: Path = PROJECT_ROOT) -> FastAPI:
    """Create the read-only mutation explorer application."""
    app = FastAPI(
        title="IDS Rule Mutation Explorer",
        version="1.0.0",
        description="Read-only API for deterministic IDS mutation experiment artifacts.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/mutations/runs")
    def mutation_runs() -> dict[str, object]:
        _require_mutation_root(project_root)
        payload = _load_mutation_explorer(list_mutation_runs, project_root)
        return _require_explorer_payload(payload)

    @app.get("/api/mutations/runs/{run_id}")
    def mutation_run(run_id: str) -> dict[str, object]:
        _validate_mutation_id(run_id)
        _require_mutation_run(project_root, run_id)
        payload = _load_mutation_explorer(
            load_mutation_run_index, project_root, run_id
        )
        return {
            key: value
            for key, value in _require_explorer_payload(payload).items()
            if key != "records"
        }

    @app.get("/api/mutations/runs/{run_id}/records")
    def mutation_records(run_id: str) -> dict[str, object]:
        _validate_mutation_id(run_id)
        _require_mutation_run(project_root, run_id)
        payload = _load_mutation_explorer(
            load_mutation_run_index, project_root, run_id
        )
        return _require_explorer_payload(payload)

    @app.get("/api/mutations/runs/{run_id}/records/{candidate_id}")
    def mutation_record(run_id: str, candidate_id: str) -> dict[str, object]:
        _validate_mutation_id(run_id)
        _validate_mutation_id(candidate_id)
        _require_mutation_run(project_root, run_id)
        try:
            payload = _load_mutation_explorer(
                load_mutation_record_detail, project_root, run_id, candidate_id
            )
        except UnknownMutationCandidate as exc:
            raise HTTPException(
                status_code=404,
                detail="Mutation explorer resource not found",
            ) from exc
        return _require_explorer_payload(payload)

    ui_dist = project_root / "ui" / "dist"
    if ui_dist.is_dir():
        app.mount("/", StaticFiles(directory=ui_dist, html=True), name="ui")

    return app


def _validate_mutation_id(value: str) -> None:
    if not _SAFE_ID.fullmatch(value):
        raise HTTPException(
            status_code=404, detail="Mutation explorer resource not found"
        )


def _require_mutation_run(project_root: Path, run_id: str) -> None:
    _require_mutation_root(project_root)
    run_path = project_root / "runs" / "mutations" / run_id
    if run_path.is_symlink() or not run_path.is_dir():
        raise HTTPException(
            status_code=404, detail="Mutation explorer resource not found"
        )


def _require_mutation_root(project_root: Path) -> None:
    ancestors = (
        project_root,
        project_root / "runs",
        project_root / "runs" / "mutations",
    )
    if any(path.is_symlink() for path in ancestors):
        raise HTTPException(
            status_code=404, detail="Mutation explorer resource not found"
        )


def _load_mutation_explorer(
    loader: Callable[..., object], *args: object
) -> object:
    try:
        return loader(*args)
    except UnknownMutationCandidate:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail="Mutation explorer configuration is invalid",
        ) from exc
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Mutation explorer configuration is invalid",
        ) from exc


def _require_explorer_payload(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=500,
            detail="Mutation explorer configuration is invalid",
        )
    return payload


app = create_app()


def main() -> None:
    """Serve the mutation explorer on a loopback-only address."""
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
