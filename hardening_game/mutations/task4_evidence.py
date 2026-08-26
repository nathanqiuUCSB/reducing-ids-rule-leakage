"""Reproducible digest over everything a Task 4 integration run depends on.

An integration result is a claim about specific bytes: these rules, replayed
against these captures, by this Suricata.  A report that states only "the
integration suite passed" cannot be checked later, because nothing says which
files it passed against.

`task4_evidence_digest` folds every such input into one digest, plus a per
component breakdown so a mismatch names the class of input that moved.  A report
records the digest it measured; a later reader recomputes it and learns
immediately whether the recorded result still applies to the tree in front of
them.

The digest deliberately covers *inputs*, not results.  It is not evidence that
the integration run passed; it is evidence that a recorded pass refers to this
tree.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import subprocess
from typing import Mapping

from hardening_game.attribution import load_baseline_clue_registry
from hardening_game.fixture import load_fixture_path
from hardening_game.mutations.clue_targets import (
    build_clue_targeted_manifest,
    load_clue_target_recipes,
)

# Every class of input the real-Suricata Task 4 integration reads.  `overall` is
# the fold of the others and is reported alongside them so the breakdown and the
# headline digest can never disagree.
EVIDENCE_COMPONENTS = (
    "suite_json",
    "fixture_json",
    "pcap",
    "dataset_recipe_module",
    "targeted_recipe_file",
    "targeted_candidate",
    "overall",
)

_DATASET_RECIPE_MODULE = Path("hardening_game/dataset_recipes.py")
_TARGETED_RECIPE_FILE = Path("fixtures/clue_targeted_mutation_recipes.json")
_CLUE_REGISTRY = Path("fixtures/baseline_clue_registry.json")


@dataclass(frozen=True)
class EvidenceDigest:
    """One digest per input class, the overall fold, and what was counted."""

    digest: str
    components: Mapping[str, str]
    counts: Mapping[str, int]
    suricata_version: str


def _fold(entries: list[tuple[str, bytes]]) -> str:
    """Hash sorted `(name, bytes)` pairs, with names inside the material.

    Names are hashed too, so moving a capture between fixtures changes the digest
    even when the bytes are reused verbatim.
    """
    digest = hashlib.sha256()
    for name, payload in sorted(entries):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        digest.update(b"\n")
    return digest.hexdigest()


def _relative_files(root: Path, pattern: str) -> list[tuple[str, bytes]]:
    return [
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in sorted(root.glob(pattern))
    ]


def suricata_version() -> str:
    """Report the Suricata build in use, or why it could not be determined."""
    try:
        result = subprocess.run(
            ["suricata", "-V"], capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable: {type(exc).__name__}"
    if result.returncode != 0:
        return f"unavailable: suricata -V exited {result.returncode}"
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else "unknown"


def rendered_targeted_candidates(*, project_root: Path) -> list[tuple[str, str, str]]:
    """Render the targeted candidates as `(id, fingerprint, rule)`, sorted.

    The rendered rules are what Suricata is actually handed, so they belong in the
    digest directly: an operator change that alters rule text moves the digest
    even though no committed file changed.
    """
    recipes = load_clue_target_recipes(project_root / _TARGETED_RECIPE_FILE)
    registry = load_baseline_clue_registry(project_root / _CLUE_REGISTRY)
    rendered: list[tuple[str, str, str]] = []
    for rule_clues in registry.rules:
        fixture = load_fixture_path(
            project_root / "fixtures/dataset" / f"{rule_clues.rule_id}.json",
            project_root=project_root,
        )
        manifest = build_clue_targeted_manifest(
            fixture_name=rule_clues.rule_id,
            baseline_rule=fixture.sanitized_rule,
            revision=fixture.revision,
            rule_clues=rule_clues,
            recipes=recipes,
        )
        for record in manifest.candidates:
            if record.status != "new":
                continue
            rendered.append(
                (
                    record.candidate.id,
                    record.candidate.fingerprint,
                    record.candidate.rule,
                )
            )
    return sorted(rendered)


def task4_evidence_digest(*, project_root: Path) -> EvidenceDigest:
    """Compute the digest over every Task 4 integration input under `project_root`."""
    project_root = project_root.resolve()
    dataset_root = project_root / "fixtures/dataset"
    pcap_root = project_root / "pcap/dataset"

    suites = _relative_files(project_root, "fixtures/dataset/*_suite.json")
    fixtures = [
        entry
        for entry in _relative_files(project_root, "fixtures/dataset/*.json")
        if not entry[0].endswith("_suite.json")
    ]
    # Capture paths are part of the material, not just the bytes: a suite that
    # pointed at a different file would otherwise digest identically.
    pcaps = _relative_files(project_root, "pcap/dataset/*/*.pcap")
    recipe_module = _relative_files(project_root, str(_DATASET_RECIPE_MODULE))
    recipe_file = _relative_files(project_root, str(_TARGETED_RECIPE_FILE))
    candidates = [
        (
            candidate_id,
            f"{fingerprint}\0{rule}".encode("utf-8"),
        )
        for candidate_id, fingerprint, rule in rendered_targeted_candidates(
            project_root=project_root
        )
    ]

    if not dataset_root.is_dir() or not pcap_root.is_dir():
        raise FileNotFoundError(
            f"{project_root} does not contain fixtures/dataset and pcap/dataset"
        )

    components = {
        "suite_json": _fold(suites),
        "fixture_json": _fold(fixtures),
        "pcap": _fold(pcaps),
        "dataset_recipe_module": _fold(recipe_module),
        "targeted_recipe_file": _fold(recipe_file),
        "targeted_candidate": _fold(candidates),
    }
    overall = hashlib.sha256()
    for component in EVIDENCE_COMPONENTS:
        if component == "overall":
            continue
        overall.update(component.encode("utf-8"))
        overall.update(b"\0")
        overall.update(components[component].encode("utf-8"))
        overall.update(b"\n")
    components["overall"] = overall.hexdigest()

    return EvidenceDigest(
        digest=components["overall"],
        components=components,
        counts={
            "suite_json": len(suites),
            "fixture_json": len(fixtures),
            "pcap": len(pcaps),
            "dataset_recipe_module": len(recipe_module),
            "targeted_recipe_file": len(recipe_file),
            "targeted_candidate": len(candidates),
        },
        suricata_version=suricata_version(),
    )


def render_evidence_report(evidence: EvidenceDigest) -> str:
    """Render the digest as the block a report can paste and a reader recompute."""
    lines = [
        f"Task 4 evidence digest: {evidence.digest}",
        f"Suricata: {evidence.suricata_version}",
        "Components:",
    ]
    for component in EVIDENCE_COMPONENTS:
        count = evidence.counts.get(component)
        suffix = "" if count is None else f"  ({count} inputs)"
        lines.append(f"  {component}: {evidence.components[component]}{suffix}")
    return "\n".join(lines)
