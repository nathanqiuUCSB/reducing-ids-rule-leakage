"""Shared path validation for read-only mutation run readers."""

from __future__ import annotations

import json
from pathlib import Path
import re


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def validate_id(value: str, *, kind: str) -> None:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ValueError(f"unsafe {kind} ID: {value!r}")


def assert_safe_path(project_root: Path, path: Path, *, label: str) -> None:
    """Reject traversal and every symlink from the root through the target."""
    if ".." in project_root.parts:
        raise ValueError("project root must not contain .. path components")
    if project_root.is_symlink():
        raise ValueError(f"project root must not be a symlink: {project_root}")
    try:
        relative = path.relative_to(project_root)
    except ValueError as error:
        raise ValueError(f"{label} must be inside project root: {path}") from error
    if ".." in relative.parts:
        raise ValueError(f"{label} path must not contain ..: {path}")
    current = project_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"{label} path contains symlink ancestor: {current}")


def safe_directory(project_root: Path, path: Path, *, label: str) -> Path:
    assert_safe_path(project_root, path, label=label)
    if not path.is_dir():
        raise ValueError(f"unknown {label}: {path.name}")
    return path


def safe_file(project_root: Path, path: Path, *, label: str) -> Path:
    assert_safe_path(project_root, path, label=label)
    if not path.is_file():
        raise ValueError(f"missing {label}: {path}")
    return path


def load_json_object(
    project_root: Path, path: Path, *, label: str
) -> dict[str, object]:
    safe_file(project_root, path, label=label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"{path} is not valid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value
