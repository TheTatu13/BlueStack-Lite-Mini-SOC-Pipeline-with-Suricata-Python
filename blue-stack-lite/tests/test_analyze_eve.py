import json
from src.analyze_eve import analyze

def test_counts_and_detections():
    sample = [
        {"event_type": "dns", "src_ip": "1.1.1.1", "dns": {"rrname": "example.com"}},
        {"event_type": "http", "src_ip": "1.1.1.1", "http": {"hostname": "test", "authorization": "Basic abc"}},
        {"event_type": "tls", "src_ip": "2.2.2.2", "tls": {"ja3": "xyz", "issuerdn": "O=Self-signed", "subject": "CN=a"}},
        {"event_type": "alert", "src_ip": "1.1.1.1", "alert": {"signature": "SIG"}},
    ]
    stats = analyze(sample)
    assert stats["totals"]["dns"] == 1
    assert stats["top_http_hosts"][0][0] == "test"
    # Self-signed TLS below threshold => no detection yet
    assert not any(d["type"] == "self_signed_tls" for d in stats["detections"])
