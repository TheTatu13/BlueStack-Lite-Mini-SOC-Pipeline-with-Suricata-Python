## BlueStack Lite — Mini SOC Pipeline

BlueStack Lite is a fast, self-contained portfolio project for blue-team workflows.  
It demonstrates how to process Suricata PCAP data, parse `eve.json`, run lightweight detections, and produce a clear, manager-friendly incident report.

### Key Features
- **SOC workflow simulation**: Ingest → Parse → Detect → Report.
- Works **offline** with provided sample Suricata events (`sample_eve.json`).
- Custom detections:
  - High DNS query volume per host (possible beaconing/exfiltration)
  - HTTP Basic credentials exposure
  - Spikes in self-signed TLS certificates
- Generates `report.md` with KPIs and recommended next actions.
- Includes automated tests and a GitHub Actions CI workflow.

### Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/analyze_eve.py --eve data/sample_eve.json --out report.md
cat report.md
pytest -q


