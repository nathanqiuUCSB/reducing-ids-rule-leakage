# Example Results

Sanitized explorer demo for one baseline-qualified rule (`et-2050340`) plus six
mutations illustrating:

- exact attribution in all recorded trials;
- unstable attribution across trials;
- never-exact attribution;
- synthetic false-positive cost;
- a representation rewrite;
- a clue-targeted semantic edit.

Install into a discoverable run directory:

```bash
python -m hardening_game.mutations.demo_data
```

The installer copies `examples/results/dataset-clue-targeted-singles-v1` to
`runs/mutations/example-clue-targeted` and refuses to overwrite a non-empty
destination.

These files omit prompts, raw provider responses, request headers, and full model
reasoning.
