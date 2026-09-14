# Running your own experiment

One command family, one path: `hardening-experiment`.

```
add-dataset  ->  baseline  ->  generate  ->  run  ->  report
   your rules    keep only     mutations +   attacker   numbers
                 rules the     PCAP suites   trials
                 attacker
                 already knows
```

Every stage reads a manifest, advances only the rules that are ready for it,
and writes the manifest back — so any stage is safe to interrupt and re-run,
and no attacker call is ever paid for twice.

The [main README](../README.md) and [reproducibility.md](reproducibility.md)
cover the separate case of re-running my published 19-rule experiment. That
dataset is hash-locked and is **not** driven from `hardening-experiment` — see
[The published 19-rule dataset](#the-published-19-rule-dataset) at the bottom.

## What you need

- Python 3.12+, this package installed (`pip install -e ".[dev]"`)
- Suricata on `PATH` (`suricata -V` should print a version) — every mutation
  and every synthesized PCAP is validated by real replay, never simulated
- An OpenAI-compatible chat-completions endpoint and API key:

  ```bash
  export LITELLM_API_KEY=sk-...
  export LITELLM_BASE_URL=https://api.openai.com/v1   # or your LiteLLM proxy, Azure, ...
  ```

  `add-dataset`, `generate`, `explain`, `complete-pcap`, `list` and `report`
  never need a key. Only `baseline`, `run` and `run-all` spend money.

## Step 0: pick a dataset

```bash
hardening-experiment list
```

This prints every dataset you have added, how many rules it holds, and what
stage each rule has reached — plus a reminder that the published 19-rule set is
run separately. With nothing added yet it tells you the `add-dataset` command
to run.

To continue a dataset you added earlier, just run the next stage on its id.
Nothing has to be re-done.

## Step 1: add your rules

Your rules go in one JSONL file, one object per line:

```jsonl
{"name": "acme-lic", "sid": 9100001, "cve": "CVE-2025-31337", "rule": "alert http any any -> $HOME_NET any (flow:established,to_server; http.method; content:\"POST\"; http.uri; content:\"/acme/lic/accept\"; sid:9100001; rev:1;)"}
{"name": "acme-rsync", "sid": 9100002, "cve": "CVE-2025-40001", "rule": "alert tcp any any -> $HOME_NET 873 (flow:established,to_server; content:\"|40|ACME|3a|\"; byte_test:4,<,16,9,relative; sid:9100002; rev:1;)"}
```

```bash
hardening-experiment add-dataset path/to/rules.jsonl --dataset-id acme-2026
```

Every field is required, and two of them are checked strictly:

- **`cve` must be exactly one CVE** (`CVE-YYYY-NNNN...`). The whole experiment
  measures whether an attacker can name *the* vulnerability a rule detects; a
  rule mapped to two CVEs has no single right answer, so it is rejected rather
  than scored against an ambiguous target.
- **`rule` must already be sanitized** — just the traffic signature. No `msg`,
  `reference`, `classtype`, or `metadata`. Those fields name the vulnerability
  outright, so leaving one in would mean measuring whether the attacker can
  read, not whether it can infer. `add-dataset` refuses an unsanitized rule and
  names the record, rather than silently stripping it and hiding the drift.

`sid`/`rev` inside the rule text are fine — the attacker never sees them.

Ingestion is idempotent: re-adding the identical file is a no-op. Re-adding a
*different* file under the same id needs `--overwrite`.

This writes `datasets/acme-2026/`:

```
datasets/acme-2026/
    source.jsonl                 # your rules, as validated
    manifest.json                # per-rule status and evidence
    related_cve_registry.json    # empty; see "Crediting near-miss answers"
```

## Step 2: the baseline gate (mandatory)

```bash
hardening-experiment baseline acme-2026 --attacker-model gpt-4.1
```

This runs the attacker **three times against each unmodified rule** and keeps
only the rules it answered with the exact target CVE all three times.

```
5 / 12 rules qualified (3/3 exact baseline). 7 rejected.
  rejected acme-smb (CVE-2025-40100): predicted CVE-2019-0708, None, CVE-2019-0708
  ...
```

This filter is the point of the whole stage. A mutation experiment can only
show that an edit *removed* the attacker's ability to name the CVE if the
attacker could reliably name it to begin with. A rule the attacker gets wrong
unmutated is a control, not a hardening opportunity — mutating it would
produce "the attacker was wrong" records that mean nothing.

Rejected rules stay in the manifest with their three predictions recorded, so
you can report what your dataset looked like before filtering. They are simply
never mutated.

**Smoke-test this before you run it on a whole dataset.** It is the first
stage that spends real money, at 3 calls per rule. Add two or three rules as a
throwaway dataset id first and check the answers look sane.

Interrupted part-way? Re-run the same command. Rules already decided are
skipped; only the undecided ones cost anything.

## Step 3: generate mutations and PCAP suites

```bash
hardening-experiment generate acme-2026
```

No API key, no cost. For every qualified rule this writes two things:

1. **The mutation matrix** — the deterministic single-mutation candidate set
   (typically 15–80 candidates depending on how many options the rule has),
   saved to `datasets/<id>/fixtures/<rule>_candidates.json`. It is a preview,
   not an input: `run` regenerates the same matrix from the same rule text.
   Reading it tells you exactly what will be tested, and how many attacker
   calls it will cost, before you pay for one.
2. **A validation suite** — synthesized traffic that makes the rule fire, plus
   a negative that makes it stop firing. The rule's own `content` literals
   *are* the exploit signature, so the traffic is mechanically derivable: place
   each literal in the buffer it belongs to, at the offset its modifiers
   demand. **Every case is then replayed through real Suricata**, and a suite
   whose positive does not actually fire is thrown away rather than written out
   as if it worked.

```
4 / 5 prepared rules have a validated suite.
83 mutation candidates to evaluate.
  needs a manual PCAP: acme-rsync - the rule's match condition depends on byte_test, which cannot be satisfied by placing literal bytes
    hardening-experiment explain acme-2026 acme-rsync
```

Automatic synthesis covers HTTP request buffers (`http.method`, `http.uri`,
`http.request_body`, `http.host`, `http.user_agent`, `http.cookie`,
`http.content_type`) and raw TCP payloads, matched by plain `content`. A rule
gated on something else is reported as `needs_manual_pcap` with the blocking
option named — that is a normal, expected outcome, not a failure, and Step 3b
finishes it in one command.

## Step 3b: finishing a rule that needs a manual PCAP

Some rules don't fire on literals alone. A `pcre` needs bytes that satisfy a
regex; a `byte_test` needs bytes that decode to a particular number. Deciding
what those bytes are is a judgement about the pattern, so the tool asks you
instead of guessing — but it only asks for that one piece.

**First, ask what is missing:**

```bash
hardening-experiment explain acme-2026 acme-rsync
```

```
acme-rsync - CVE-2025-40001
  rule: alert tcp any any -> $HOME_NET 873 (flow:established,to_server; content:"|40|ACME|3a|"; byte_test:4,<,16,9,relative; sid:9100002; rev:1;)

Already determined automatically:
  protocol tcp, destination port 873, flow established,to_server
  buffer payload:
    content-0: '@ACME:' (40 41 43 4d 45 3a)

You need to supply bytes that satisfy:
  byte_test: the 4 bytes at offset 9 after the end of the previous match must decode as a big-endian integer less than 16

Those bytes are appended after content-0 in buffer payload.

Supply them with:
  hardening-experiment complete-pcap acme-2026 acme-rsync \
      --fill-text "<the bytes that satisfy the above>"
  (use --fill-hex for non-printable bytes, and --insert-after <predicate-id> to place them elsewhere)
```

**Then supply just that piece:**

```bash
hardening-experiment complete-pcap acme-2026 acme-rsync \
  --fill-hex "41 41 41 41 41 41 41 41 41 00 00 00 05"
```

Nine filler bytes to reach offset 9, then a big-endian `5`, which is less than
16. Use `--fill-text` for printable bytes (`\xNN` escapes work), `--fill-hex`
for anything else.

Everything else — the handshake, the port, the direction, the anchor content,
the negative case — is filled in around your bytes, and the result is
immediately replayed through real Suricata:

```
Supplied bytes satisfied the rule; 2 cases written.
Next: hardening-experiment generate acme-2026  # picks up the rest
```

A wrong guess tells you so, and says where your bytes were placed, instead of
leaving you to wonder:

```
the supplied bytes did not satisfy the rule under real Suricata (P0-manual-canonical).
Check the requirements with `explain` and try again - they were inserted after content-0.
```

Nothing is written on failure, and the rule stays exactly where it was, so you
can try again as many times as you like. If your bytes belong somewhere other
than the anchor `explain` names, pass `--insert-after <predicate-id>` with one
of the predicate ids `explain` listed.

<details>
<summary>What <code>complete-pcap</code> is doing under the hood</summary>

The same thing you would do by hand with `scapy` or
`hardening_game/pcap/suite_builders.py`:

```python
from pathlib import Path
from hardening_game.pcap.suite_builders import (
    build_established_tcp_stream,
    http_request,
    write_case_pcap,
)

payload = http_request("GET", "/vulnerable-endpoint")
packets = build_established_tcp_stream(
    payload,
    port=80,
    direction="to_server",   # "to_client" for a response-triggered rule
    segment_sizes=None,      # or a tuple of chunk sizes to test segmentation
    retransmit_segment=None, # or a segment index to duplicate, for retransmit cases
)
write_case_pcap(packets, Path("pcap/my-rule/positive.pcap"))
```

The handshake matters more than it looks. Most real rules carry
`flow:established`, which means Suricata requires a real SYN → SYN-ACK → ACK
exchange before it tracks the connection at all — so a single raw packet whose
payload matches the rule's content exactly still stays silent, because
Suricata never reaches app-layer inspection. That is not a quirk of this
framework, it is how Suricata always behaves, and the fix is a realistic PCAP
rather than a code change. `build_established_tcp_stream` builds the full
handshake, the request, and a clean teardown, with fixed
addresses/ports/sequence numbers/timestamps, so re-running it produces a
byte-identical PCAP.

You can still build suites entirely by hand if you want cases the synthesizer
does not produce (segmentation, retransmits, predicate-by-predicate negatives)
— write them into `datasets/<id>/fixtures/<rule>_suite.json` in the format
under [Artifacts](#artifacts) and `run` will use them.
</details>

## Step 4: run the experiment

```bash
hardening-experiment run acme-2026 --attacker-model gpt-4.1
```

For each prepared rule, every candidate in its mutation matrix is:

1. syntax-checked by real Suricata,
2. replayed against the suite — **a candidate whose positive case stops firing
   is rejected, not measured**, because a mutation that breaks detection is not
   a hardening result,
3. shown to the attacker three times, independently.

One resumable run directory per rule, under
`runs/mutations/acme-2026/experiment/<rule>/`. Interrupted? Re-run the same
command: finished rules are skipped, and within a rule, candidates and
individual trial slots already recorded are never re-paid for.

## Step 5: report

```bash
hardening-experiment report acme-2026
```

```
Rules analyzed: 5
Contributing rules: 5
Exact emergent misses: 31
Effective emergent misses: 24
Closely related predictions discounted: 7
...
Artifacts: runs/mutations/acme-2026/experiment
```

This writes `attribution_report.json` and `attribution_report.md` into that
directory, using the same analyzer the published 19-rule result was reported
with — so your numbers mean the same thing as mine. The independent unit is
the rule, not the mutation; see [methodology.md](methodology.md) for what each
metric does and does not claim.

## The whole flow in one command

Once you have been through it once:

```bash
hardening-experiment add-dataset rules.jsonl --dataset-id acme-2026
hardening-experiment run-all acme-2026 --attacker-model gpt-4.1
```

`run-all` chains baseline → generate → run → report and stops at the first
stage that has nothing to hand forward (no rule qualified, or no rule
prepared). It will not stop for a `needs_manual_pcap` rule: those are skipped
and reported, and you can finish them and re-run later.

## Changing the attacker model

`--attacker-model` takes any model id your endpoint serves. Nothing in the
mutation engine, the evaluator, or the scoring is tied to a particular model.
Change the model and the endpoint together:

```bash
export LITELLM_API_KEY=sk-...
export LITELLM_BASE_URL=https://api.openai.com/v1
hardening-experiment run-all acme-2026 --attacker-model claude-sonnet-4-5
```

`LITELLM_BASE_URL` (or `--base-url`) must point at an OpenAI-compatible
chat-completions endpoint reachable from wherever you run the command — there
is no default that works outside my network. `--api-key-env` reads the key from
a differently-named variable if you are juggling providers.

**The baseline gate is model-specific, and that is the point.** Qualification
means *this* attacker knows *this* rule, so switching models means re-running
the gate. Use a separate `--dataset-id` per attacker (`acme-2026-gpt41`,
`acme-2026-sonnet`) if you want to compare two attackers over the same rules;
the qualified subsets will differ, which is itself a result.

One model-behavior note, not a bug: reasoning models with a large hidden
reasoning budget (my own runs used `gpt-5.5`) occasionally return an empty
visible response at the default token ceiling. The client retries once
automatically.

## Flags worth knowing

| Flag | Stage | What it does |
| --- | --- | --- |
| `--attacker-trials N` | `baseline`, `run` | Trials per rule or candidate (default 3). Lower for a cheap smoke test; durable-effect claims need 3. |
| `--no-resume` | `baseline`, `generate`, `run` | Redo work already recorded. On `baseline` and `run` this spends the attacker calls again. |
| `--overwrite` | `add-dataset` | Replace an existing dataset id whose source file differs. |
| `--insert-after ID` | `complete-pcap` | Place your bytes after a different predicate than the anchor `explain` names. |
| `--benign` | `run` | Also replay mapped benign captures (see below). |
| `--project-root PATH` | all | Use a different checkout's `datasets/` and `runs/`. |

`hardening-experiment <subcommand> --help` is the authoritative list.

## Crediting near-miss answers

An attacker that answers `CVE-2024-0012` when the target was `CVE-2025-0108`
may not really have been fooled — those can be adjacent advisories in the same
component. `datasets/<id>/related_cve_registry.json` starts empty; add a
reviewed entry per directional pair you have actually checked:

```json
{
  "version": 1,
  "entries": [
    {
      "target_cve": "CVE-2025-0108",
      "predicted_cve": "CVE-2024-0012",
      "tier": "closely_related",
      "vendor": "Palo Alto Networks",
      "product": "PAN-OS",
      "rationale": "Closely related management-interface authentication bypasses.",
      "provenance": "Reviewed vendor advisories, 2026-01-14."
    }
  ]
}
```

`report` then separates *exact* misses (the attacker did not name the target)
from *effective* misses (it did not name anything close either). Registered
pairs are discounted from the effective count. Curate this by hand, from
advisories — an unreviewed registry inflates your own result. `report` is
cheap to re-run, so add entries and re-report as you review.

## Benign false-positive checks

Benign replay is **off by default** for new datasets, because it needs a
`benign_sources/` corpus with per-fixture mappings that a freshly added
dataset does not have. The report then shows benign precision as explicitly
unmeasured — not as a zero false-positive rate nobody measured.

To turn it on, register a benign PCAP corpus under `benign_sources/` following
the existing `benign_registry.json` / `fixture_benign_mappings.json` format,
mapping sources to your fixture *names*, then pass `--benign` to `run`.

## Artifacts

```
datasets/<id>/
    source.jsonl                       # your rules, as validated
    manifest.json                      # per-rule status + baseline/suite/mutation evidence
    related_cve_registry.json          # your curated near-miss pairs
    fixtures/<rule>.json               # fixture: rule, target CVE, suite pointer
    fixtures/<rule>_suite.json         # validation cases
    fixtures/<rule>_candidates.json    # the mutation matrix, for inspection
    pcap/<rule>/*.pcap                 # synthesized traffic
runs/mutations/<id>/baseline/<rule>/   # the 3 baseline trials per rule
runs/mutations/<id>/experiment/<rule>/ # the real experiment, per rule
runs/mutations/<id>/experiment/attribution_report.{json,md}
```

Inside a run directory:

- `results.jsonl` — one traffic-evaluation record per candidate (syntax,
  positive recall, false-positive rates). Read this as "did the candidate reach
  evaluation", **not** as the source of attacker outcomes.
- `attacker_trials.jsonl` — the authoritative per-trial attacker record
  (`candidate_id`, `trial_index`, `status`, `prediction`). This is what a
  resume fills in. Always read attacker outcomes from here: `results.jsonl`'s
  single status field is not rewritten by a trial-only resume and goes stale.
- `summary.json` / `summary.md` — a human-readable rollup.

The `manifest.json` status per rule is the pipeline's own record of where each
rule stands: `ingested` → `baseline_qualified` | `baseline_rejected` →
`suite_needs_manual_pcap` → `mutations_generated` → `experiment_complete`.

## The published 19-rule dataset

My own 19-rule experiment is hash-locked against a pre-registered manifest so
the published result is auditable byte for byte. It is reproduced with the
existing commands, not through `hardening-experiment`:

```bash
hardening-mutations \
  --experiment-manifest experiments/single-clue-targeted-v1/manifest.json \
  --dataset-fixtures --preflight
```

See [reproducibility.md](reproducibility.md). It is deliberately never
re-qualified or re-synthesized through this pipeline — re-deriving its
fixtures would break the hashes that make it reproducible.

## Known gaps

Called out rather than left to be discovered:

- `hardening-dashboard`'s Mutation Explorer reads only the legacy flat
  `fixtures/dataset_manifest.json`, so runs from this pipeline do not appear in
  it. Use `hardening-experiment report` instead.
- Automatic PCAP synthesis does not cover non-HTTP/non-TCP protocols (DNS,
  TLS, SMB), nor rules gated on `flowbits:isset`, `threshold`, or negated
  content. These come back as `needs_manual_pcap`; `complete-pcap` handles the
  `pcre`/`byte_test` cases, and the rest need a hand-built suite.
- The generated suite is one positive and one negative per rule. That is enough
  to gate recall, but a richer negative set is what sharpens the
  synthetic-false-positive signal — see the `<details>` block in Step 3b for
  adding your own cases.

## If you want the full research rigor

The clue registry, targeted-recipe system, and hash-locked manifest
(`experiments/single-clue-targeted-v1/`) exist to make *my* specific result
auditable — not because you need them to run your own experiment. If you do
want that level of rigor (ranked clues per rule, recipes that specifically
target them, a frozen pre-registered manifest), read
[methodology.md](methodology.md) and [architecture.md](architecture.md) first,
then `hardening_game/mutations/clue_manifest.py` and
`hardening_game/mutations/clue_targets.py`. It is a substantially bigger lift
than the flow above, and only worth it if you are publishing a comparable
claim.
