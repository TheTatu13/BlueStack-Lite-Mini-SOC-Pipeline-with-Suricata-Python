# BlueStack Lite — Mini SOC Project

A fast, interview-ready blue-team portfolio project. It runs Suricata on PCAPs (offline), parses `eve.json`,
applies simple detections, and produces a concise incident report with KPIs you can demo live.

## Why this stands out
- **Real SOC flow**: ingest (Suricata) → parse/enrich (Python) → detections → **report.md**.
- **ATS-friendly**: clear Python, tests, detections, and instructions.
- **Works offline**: includes a synthetic `sample_eve.json` so you can demo without downloading PCAPs.

## Features
- Run Suricata on one or more PCAPs and export `eve.json`.
- Parse events and compute KPIs (top talkers, alerts by signature, DNS/TLS/HTTP stats).
- Lightweight detections:
  - Excessive DNS queries per host (possible exfiltration/beaconing)
  - Cleartext HTTP Basic credentials (risky auth exposure)
  - Self-signed TLS certificate usage spikes
- Generate `report.md` with findings and next actions.

## Quickstart (without PCAPs)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python src/analyze_eve.py --eve data/sample_eve.json --out report.md
cat report.md
pytest -q
```

## Using with Suricata on real PCAPs
1. Install Suricata (`sudo apt install suricata`) or use Docker (optional).
2. Put PCAPs into `./pcaps/` (create the folder).
3. Run Suricata in offline mode to generate `eve.json`:
```bash
mkdir -p out && suricata -r pcaps/your.pcap -l out --set outputs.eve.enabled=yes
# eve.json will be at ./out/eve.json (path can vary by distro/config)
```
4. Parse & detect:
```bash
python src/analyze_eve.py --eve out/eve.json --out report.md
```

### Custom Suricata rules
Add/modify rules in `detections/suricata/local.rules` and (optionally) load them via your `suricata.yaml`:
```
rule-files:
  - local.rules
```


- **Scope**: “I built a mini SOC pipeline around Suricata. It parses eve.json, computes KPIs, flags risky patterns (DNS bursts, basic auth over HTTP, self-signed TLS), and outputs a readable report with next steps.”
- **Detections**: “I wrote small, explainable heuristics and paired them with Suricata rules in `detections/`. I can extend them into Sigma-style logic or forward to a SIEM.”
- **Quality**: “Repo has tests, a clear README, and is easily runnable. I kept it dependency-light.”
- **Next**: “Swap SQLite/Parquet storage, add Sigma, ship to OpenSearch, and wire Slack/email alerts.”

## Repo structure
```
blue-stack-lite/
├─ README.md
├─ requirements.txt
├─ src/
│  ├─ analyze_eve.py
│  └─ run_suricata.sh
├─ data/
│  └─ sample_eve.json
├─ detections/
│  └─ suricata/
│     └─ local.rules
├─ tests/
│  └─ test_analyze_eve.py
├─ .github/
│  └─ workflows/
│     └─ python.yml
├─ .gitignore
├─ LICENSE
```

## License
MIT
