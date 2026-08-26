# Reproducibility

## Requirements

- Python 3.12+
- Suricata on `PATH` for traffic validation / integration tests
- Optional LiteLLM-compatible API for live attacker trials
- Node.js 20+ for the Mutation Explorer UI

## Deterministic checks (no API key)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,dashboard]"
pytest -q -m "not integration"
```

With Suricata installed:

```bash
pytest -q -m integration
```

## Manifest preflight

```bash
hardening-mutations \
  --experiment-manifest experiments/single-clue-targeted-v1/manifest.json \
  --dataset-fixtures \
  --attacker-model gpt-5.5 \
  --run-id dataset-clue-targeted-singles-v1 \
  --preflight
```

Preflight validates locks without writing attacker traffic or calling an API.

## Explorer demo

```bash
python -m hardening_game.mutations.demo_data
hardening-dashboard
```

Then open the UI and select `example-clue-targeted`.

## Optional live attacker trials

Set:

```bash
export LITELLM_API_KEY=...
export LITELLM_BASE_URL=https://your-compatible-endpoint/v1
```

Attacker trials append to `attacker_trials.jsonl` and can be resumed. Do not
re-run without `--resume` in a populated output directory.
