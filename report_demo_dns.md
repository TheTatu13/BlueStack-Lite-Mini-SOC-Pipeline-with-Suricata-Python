# BlueStack Lite — Report

## Event totals by type
- dns: 60

## Top alerts
_None_

## Top source IPs
- 192.168.56.10: 60

## Top destination IPs
_None_

## Top DNS qnames
- exfil.example: 60

## Top HTTP hosts
_None_

## Top TLS JA3
_None_

## Detections
- [suspicious_dns_volume] src=192.168.56.10 count=60 — High DNS query volume (60) may indicate beaconing or exfiltration.

## Next actions
- Pivot to SIEM with these fields (src_ip, dest_ip, ja3, http.host) and hunt for related activity.
- If HTTP Basic seen, enforce HTTPS and disable basic auth immediately.
- Investigate top DNS talkers; verify domains; consider EDR triage on hosts.