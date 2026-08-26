# Architecture

```text
Fixture + PCAP suite
        |
        v
Mutation engine (families + dependencies + taxonomy)
        |
        v
Candidate specs / hash-locked experiment manifest
        |
        v
Suricata syntax check + positive recall + synthetic/benign precision
        |
        v
Resumable multi-trial attacker evaluation
        |
        v
Related-CVE attribution + clue scoring
        |
        v
JSONL artifacts -> reports / Mutation Explorer
```

## Core packages

- `hardening_game/mutations/` — candidate generation, evaluation, reporting, explorer.
- `hardening_game/suricata/` — rule parsing and Suricata validation/replay.
- `hardening_game/pcap/` — synthetic suite builders.
- `hardening_game/attribution/` — related-CVE registry and clue scoring.
- `hardening_game/benign/` — optional benign-corpus precision measurements.
- `hardening_game/api.py` + `ui/` — read-only Mutation Explorer.

## Experiment locking

`experiments/single-clue-targeted-v1/manifest.json` freezes the exact candidate
set, rule strings, and registry hashes used by the final single-mutation
experiment. Preflight validation checks those locks before any attacker call.
