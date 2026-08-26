# Methodology

## Baseline qualification

A rule enters the primary analysis cohort only when the attacker predicts the
exact target CVE in all three baseline trials. Rules that fail baseline
qualification are controls, not hardening successes.

## Detection metrics

- **Positive recall:** fraction of signature-positive PCAPs that still alert.
- **Synthetic false-positive rate:** fraction of synthetic near-miss / negative
  PCAPs that alert.
- **Benign false-positive rate:** fraction of registered benign captures that
  alert (optional; requires the benign downloader).

## Attribution labels

Predictions are compared to the ground-truth CVE using a reviewed related-CVE
registry:

- **exact** — predicted CVE matches the target;
- **close** — reviewed closely related CVE;
- **non_close** — reviewed but not closely related;
- **unreviewed** — pair not yet classified.

## Obscurity endpoints

- **Unstable miss:** exact in 1 or 2 of 3 trials.
- **Never exact:** wrong in all 3 trials.
- **Durable major-clue obscurity:** never exact and supported by major-clue
  disruption evidence across trials.

Exact-CVE misses are weaker than durable major-clue obscurity. The final
experiment produced durable exact misses for a small minority of candidates and
zero durable major-clue obscurity in the complete primary cohort.
