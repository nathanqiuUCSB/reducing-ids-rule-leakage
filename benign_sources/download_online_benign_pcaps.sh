#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-online_benign_pcaps}"
mkdir -p \
  "$ROOT/level1/http" \
  "$ROOT/level1/smtp" \
  "$ROOT/level1_to_level3/rsync" \
  "$ROOT/level1_to_level2/postgresql" \
  "$ROOT/logs"

download() {
  local url="$1"
  local output="$2"
  echo "Downloading: $output"
  if curl --location --fail --retry 3 --retry-delay 2 \
      --output "$output.part" "$url"; then
    mv "$output.part" "$output"
  else
    rm -f "$output.part"
    echo "FAILED: $url" | tee -a "$ROOT/logs/download_failures.txt" >&2
  fi
}

# Level 1 — HTTP
download "https://wiki.wireshark.org/uploads/27707187aeb30df68e70c8fb9d614981/http.cap" \
  "$ROOT/level1/http/http.cap"
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http_gzip.cap" \
  "$ROOT/level1/http/http_gzip.cap"
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http-chunked-gzip.pcap" \
  "$ROOT/level1/http/http-chunked-gzip.pcap"
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/tcp-ethereal-file1.trace" \
  "$ROOT/level1/http/tcp-ethereal-file1.trace"
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http_redirects.pcapng" \
  "$ROOT/level1/http/http_redirects.pcapng"

# Level 1 / Level 2 candidate — SMTP, IMF, and TNEF
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/smtp.pcap" \
  "$ROOT/level1/smtp/smtp.pcap"
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/sample-imf.pcap.gz" \
  "$ROOT/level1/smtp/sample-imf.pcap.gz"
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/sample-TNEF.pcap.gz" \
  "$ROOT/level1/smtp/sample-TNEF.pcap.gz"

# Level 1 / Level 2 / possible Level 3 — rsync
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/EmergeSync.cap" \
  "$ROOT/level1_to_level3/rsync/EmergeSync.cap"

# Level 1 / Level 2 — PostgreSQL
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/pgsql.cap.gz" \
  "$ROOT/level1_to_level2/postgresql/pgsql.cap.gz"
download "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/pgsql-jdbc.pcap.gz?download=1" \
  "$ROOT/level1_to_level2/postgresql/pgsql-jdbc.pcap.gz"
download "https://raw.githubusercontent.com/Lekensteyn/wireshark-notes/master/tls/pgsql-ssl.pcapng" \
  "$ROOT/level1_to_level2/postgresql/pgsql-ssl.pcapng"

echo
echo "Generating SHA-256 manifest..."
find "$ROOT" -type f \
  ! -path "$ROOT/logs/*" \
  ! -name '*.part' \
  ! -name 'SHA256SUMS.txt' \
  -print0 | sort -z | xargs -0 sha256sum > "$ROOT/SHA256SUMS.txt"

cat <<'EOF'

Small-capture download pass complete.

Large datasets were intentionally not downloaded automatically:

1. Zenodo 2026 benign PCAP dataset
   Record: https://zenodo.org/records/19206234
   Approximate archive size: 6.9 GB

2. CICIDS2017 Monday benign PCAP
   Dataset page: https://www.unb.ca/cic/datasets/ids-2017.html
   Approximate Monday size: 11 GB

Validation examples:

  capinfos online_benign_pcaps/level1/http/http.cap

  tshark -r online_benign_pcaps/level1/smtp/sample-TNEF.pcap.gz \
    -Y "smtp or imf or tnef"

  tshark -r online_benign_pcaps/level1_to_level3/rsync/EmergeSync.cap \
    -Y "tcp.port == 873" -V

  tshark -r online_benign_pcaps/level1_to_level2/postgresql/pgsql-jdbc.pcap.gz \
    -Y "pgsql or tcp.port == 5432"

Do not promote a capture to Level 2 or Level 3 until packet inspection confirms
the exact product and operation claimed in the research manifest.
EOF
