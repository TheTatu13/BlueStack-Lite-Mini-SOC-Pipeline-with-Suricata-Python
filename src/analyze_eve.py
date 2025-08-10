#!/usr/bin/env python3
import json
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List

def load_eve(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                # allow array style export too
                if line.startswith("[") or line.endswith("]"):
                    # read full file as array
                    f.seek(0)
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                yield item
                    return

def top(counter: Counter, n=10) -> List:
    return counter.most_common(n)

def analyze(events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    totals = Counter()
    sigs = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    dns_qnames = Counter()
    http_hosts = Counter()
    tls_ja3 = Counter()

    detections = []

    # per-host metrics
    host_dns_counts = defaultdict(int)
    host_selfsigned_tls = defaultdict(int)
    host_basic_auth = defaultdict(int)

    for ev in events:
        evt_type = ev.get("event_type")
        totals[evt_type] += 1

        src = ev.get("src_ip")
        dst = ev.get("dest_ip") or ev.get("dst_ip")
        if src: src_ips[src] += 1
        if dst: dst_ips[dst] += 1

        if evt_type == "alert":
            sig = ev.get("alert", {}).get("signature")
            if sig: sigs[sig] += 1

        if evt_type == "dns":
            q = ev.get("dns", {}).get("rrname") or ev.get("dns", {}).get("query", {}).get("rrname")
            if q:
                dns_qnames[q] += 1
            if src:
                host_dns_counts[src] += 1

        if evt_type == "http":
            http = ev.get("http", {})
            host = http.get("hostname") or http.get("http_host")
            if host: http_hosts[host] += 1
            # crude indicator of basic auth (Suricata can surface this via fields; fallback to header match if present)
            auth = http.get("authorization") or http.get("http_authorization")
            if auth and "basic " in auth.lower() and src:
                host_basic_auth[src] += 1

        if evt_type == "tls":
            tls = ev.get("tls", {})
            ja3 = tls.get("ja3")
            if ja3: tls_ja3[ja3] += 1
            if tls.get("subject") and "O=Self-signed" in tls.get("issuerdn", "") and src:
                host_selfsigned_tls[src] += 1

    # Heuristic detections
    # 1) Excessive DNS per host (threshold kept modest for demo)
    for host, cnt in sorted(host_dns_counts.items(), key=lambda x: x[1], reverse=True):
        if cnt >= 50:
            detections.append({
                "type": "suspicious_dns_volume",
                "src_ip": host,
                "count": cnt,
                "reason": f"High DNS query volume ({cnt}) may indicate beaconing or exfiltration."
            })

    # 2) HTTP Basic auth seen
    for host, cnt in host_basic_auth.items():
        if cnt > 0:
            detections.append({
                "type": "http_basic_auth",
                "src_ip": host,
                "count": cnt,
                "reason": "HTTP Basic credentials observed — risk of credential exposure."
            })

    # 3) Self-signed TLS spike
    for host, cnt in host_selfsigned_tls.items():
        if cnt >= 5:
            detections.append({
                "type": "self_signed_tls",
                "src_ip": host,
                "count": cnt,
                "reason": f"Multiple self-signed TLS certs observed ({cnt})."
            })

    return {
        "totals": totals,
        "top_alerts": top(sigs),
        "top_src_ips": top(src_ips),
        "top_dst_ips": top(dst_ips),
        "top_dns": top(dns_qnames),
        "top_http_hosts": top(http_hosts),
        "top_tls_ja3": top(tls_ja3),
        "detections": detections,
    }

def render_report(stats: Dict[str, Any]) -> str:
    lines = []
    lines.append("# BlueStack Lite — Report")
    lines.append("")
    lines.append("## Event totals by type")
    for k, v in stats["totals"].items():
        lines.append(f"- {k}: {v}")
    lines.append("")

    def sec(title, items):
        lines.append(f"## {title}")
        if not items:
            lines.append("_None_")
        else:
            for name, count in items:
                lines.append(f"- {name}: {count}")
        lines.append("")

    sec("Top alerts", stats["top_alerts"])
    sec("Top source IPs", stats["top_src_ips"])
    sec("Top destination IPs", stats["top_dst_ips"])
    sec("Top DNS qnames", stats["top_dns"])
    sec("Top HTTP hosts", stats["top_http_hosts"])
    sec("Top TLS JA3", stats["top_tls_ja3"])

    lines.append("## Detections")
    if not stats["detections"]:
        lines.append("_None_")
    else:
        for d in stats["detections"]:
            lines.append(f"- [{d['type']}] src={d.get('src_ip','?')} count={d.get('count',0)} — {d['reason']}")
    lines.append("")
    lines.append("## Next actions")
    lines.append("- Pivot to SIEM with these fields (src_ip, dest_ip, ja3, http.host) and hunt for related activity.")
    lines.append("- If HTTP Basic seen, enforce HTTPS and disable basic auth immediately.")
    lines.append("- Investigate top DNS talkers; verify domains; consider EDR triage on hosts.")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", required=True, help="Path to Suricata eve.json (or sample_eve.json)")
    ap.add_argument("--out", required=True, help="Output report path (Markdown)")
    args = ap.parse_args()

    events = list(load_eve(args.eve))
    stats = analyze(events)
    report = render_report(stats)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[+] Report written to {args.out}")

if __name__ == "__main__":
    main()
