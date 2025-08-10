# BlueStack Lite — Report

## Event totals by type
- dns: 60
- tls: 6
- http: 1
- alert: 1

## Top alerts
- DEMO Suspicious Activity: 1

## Top source IPs
- 192.168.56.10: 60
- 10.42.0.7: 6
- 10.0.0.9: 2

## Top destination IPs
_None_

## Top DNS qnames
- exfil.example: 60

## Top HTTP hosts
- insecure.local: 1

## Top TLS JA3
_None_

## Detections
- [suspicious_dns_volume] src=192.168.56.10 count=60 — High DNS query volume (60) may indicate beaconing or exfiltration.
- [http_basic_auth] src=10.0.0.9 count=1 — HTTP Basic credentials observed — risk of credential exposure.
- [self_signed_tls] src=10.42.0.7 count=6 — Multiple self-signed TLS certs observed (6).

## Next actions
- Pivot to SIEM with these fields (src_ip, dest_ip, ja3, http.host) and hunt for related activity.
- If HTTP Basic seen, enforce HTTPS and disable basic auth immediately.
- Investigate top DNS talkers; verify domains; consider EDR triage on hosts.