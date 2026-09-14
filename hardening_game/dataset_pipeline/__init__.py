"""Unified dataset-to-experiment pipeline: ingest, baseline-gate, generate, run, report.

This package is additive orchestration glue over the existing mutation engine,
evaluator, and reporting modules. It never modifies the project's original
19-rule dataset, its fixtures, or its hash-locked experiment manifest - those
keep working exactly as they do today via the existing `hardening-mutations`
commands. Everything here operates on datasets added through
`hardening-experiment add-dataset`, isolated under `datasets/<dataset-id>/`.
"""
