# Security

## Untrusted rules and traffic

This framework evaluates Suricata rules against PCAP files. Treat untrusted rules
and captures as potentially hostile:

- run Suricata and experiment commands in an isolated environment;
- do not point the evaluator at production networks;
- review downloaded benign-capture sources before enabling them.

## Secrets

- Keep API keys in `.env` or the process environment.
- Never commit `.env`.
- Do not store provider request headers, API keys, or raw model transcripts in
  tracked example results.

## Reporting issues

If you find a security-sensitive issue in this repository, open a private report
with the repository owner rather than filing a public issue with exploit details.
