# BlueStack Lite — Report

## Event totals by type
- tls: 6

## Top alerts
_None_

## Top source IPs
- 10.42.0.7: 6

## Top destination IPs
_None_

## Top DNS qnames
_None_

## Top HTTP hosts
_None_

## Top TLS JA3
_None_

## Detections
- [self_signed_tls] src=10.42.0.7 count=6 — Multiple self-signed TLS certs observed (6).

## Next actions
- Pivot to SIEM with these fields (src_ip, dest_ip, ja3, http.host) and hunt for related activity.
- If HTTP Basic seen, enforce HTTPS and disable basic auth immediately.
- Investigate top DNS talkers; verify domains; consider EDR triage on hosts.