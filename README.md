# SIEMulate

**Local-First Detection Intelligence & Entity Correlation Engine**

The judgment layer that transforms raw sensor data into **attack chain narratives instead of alert noise**.

Built by Rayyan Umair - *Technology evolves quickly. Responsibility does not.*

---

# What it does

SIEMulate ingests structured events from LogClaw, PacketStrike, and DNStalon, evaluates them against a live Sigma rule library, and tracks the behavioral state of every entity (user, host, IP) over time to produce:

* risk-scored entity profiles
* correlated attack chain reconstructions
* explainable 5W+H investigation narratives
* auto-generated DuckDB investigation queries
* MITRE ATT&CK technique mapping

Every detection becomes a **human-readable escalation narrative**:

### Instead of raw rule matches:
SIGMA MATCH: suspicious_powershell.yml - host: WKSTN-04
SIGMA MATCH: lateral_movement_smb.yml - host: WKSTN-04

### You get:

* WHO triggered it (entity + risk score)
* WHAT the rule detected (plain-English Sigma summary)
* WHERE it happened (originating host + target asset)
* WHEN the chain started vs. now
* WHY it fired (exact Sigma selection logic)
* HOW to investigate (auto-generated DuckDB SQL query)

No SIEM complexity. No alert fatigue. No manual correlation.

---

# System Overview

SIEMulate is a single-process intelligence engine built around three core subsystems:

## Sigma Engine

The detection layer.

Handles:

* Sigma YAML rule loading via pySigma
* real-time rule evaluation against incoming events
* rule hot-reload without restart
* community rule compatibility

## Correlation Engine

The judgment layer.

Handles:

* entity state tracking (users, hosts, IPs)
* risk score accumulation and time-decay
* attack chain detection (rules firing within 15-minute window)
* escalation narrative generation
* MITRE ATT&CK technique mapping

## Replay Engine

The simulation layer.

Handles:

* historic JSON log file ingestion
* fast-forward playback at configurable speed
* live alert firing against replayed events
* rule regression testing against known attacks

---

# Core Concept

SIEMulate does NOT treat rule matches as alerts.

It treats them as:

> **behavioral evidence of entities moving through an attack chain**

---

# Universal Event Schema

Every inbound event is normalised into:

```json
{
  "event_id": "uuid",
  "timestamp": "UTC ISO8601",
  "source": "logclaw | packetstrike | dnstalon | replay",

  "entity": {
    "name": "admin",
    "type": "user | host | ip",
    "host": "WKSTN-04"
  },

  "event": {
    "type": "auth | process | network | config | dns",
    "action": "login | execute | connect | modify",
    "severity": 0
  },

  "mitre": {
    "technique_id": "T1059.001",
    "tactic": "Execution"
  },

  "raw_payload": { }
}
```

---

# Quick Start

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

## 2. Add Sigma Rules

Drop any Sigma YAML rule files into the `rules/` directory:

```bash
rules/
  suspicious_powershell.yml
  lateral_movement_smb.yml
  brute_force_login.yml
```

Community rules: https://github.com/SigmaHQ/sigma

## 3. Start SIEMulate

```bash
python main.py
```

Runs:

* FastAPI server (default: `http://0.0.0.0:8002`)
* Sigma rule engine
* Correlation engine
* WebSocket stream at `ws://localhost:8002/ws/alerts`

## 4. Replay a Historic Attack

```bash
POST http://localhost:8002/replay/start
{ "file": "attack_log.json", "speed": 10.0 }
```

---

# Risk Scoring

SIEMulate maintains a risk score (0–100) per entity.

| Score | Level    | Meaning                                  |
|-------|----------|------------------------------------------|
| 0–24  | LOW      | Normal activity, no detections           |
| 25–49 | MEDIUM   | One or more rules fired                  |
| 50–74 | HIGH     | Multiple rules, possible chain forming   |
| 75+   | CRITICAL | Attack chain confirmed - immediate action|

Risk scores decay over time. Quiet entities cool down automatically.

---

# Attack Chain Reconstruction

The killer feature.

When two or more distinct Sigma rules fire on the same entity within the 15-minute correlation window, SIEMulate reconstructs the attack chain:

Initial Access
↓
Credential Abuse         [T1110 - 10:22 UTC]
↓
Suspicious Execution     [T1059 - 10:24 UTC]
↓
Privilege Escalation     [T1068 - 10:31 UTC]
↓
Lateral Movement         [T1021 - 10:38 UTC]

Each stage links back to:

* the Sigma rule that fired
* the raw log event that triggered it
* the auto-generated investigation SQL query

---

# 5W+H Investigation Engine

Every alert is transformed into:

| Component | SIEMulate Output |
|-----------|-----------------|
| **WHO**   | Entity name + risk score (e.g. "admin - Risk 82/100") |
| **WHAT**  | Plain-English Sigma rule summary |
| **WHERE** | Originating host + target asset |
| **WHEN**  | Chain start time vs. current detection timestamp |
| **WHY**   | Exact `selection` logic from the Sigma YAML |
| **HOW**   | Auto-generated DuckDB SQL investigation query |

---

# Sigma Rule Support

SIEMulate uses pySigma for native Sigma YAML parsing.

Supported:

* standard Sigma field mappings
* condition logic (and, or, not, 1 of, all of)
* YAML rule hot-reload (no restart required)
* community rule packs (SigmaHQ/sigma)

---

# Replay Engine

Upload a `.json` file of historic log events and SIEMulate replays them through the full detection pipeline - firing alerts, building chains, and scoring entities as if the attack were happening live.

Use cases:

* test new Sigma rules against known attacks
* demonstrate the platform in interviews
* regression test after rule changes
* train detection logic on real incident data

---

# AI Layer (Optional)

AI is NOT required.

When enabled, it acts as:

> a SOC analyst assistant - not a detector

It can:

* explain attack chains in plain English
* summarise entity risk profiles
* suggest investigation next steps
* generate incident reports

It cannot:

* write detection logic
* replace the correlation engine
* fabricate log evidence

Supported providers:

* Local LLMs (Ollama / llama.cpp)
* OpenAI
* Gemini
* Groq
* Disabled mode (fully offline)

---

# NetRaptor Ecosystem

SIEMulate is the **detection intelligence layer** of the NetRaptor platform.

It consumes behavioral data from:

* **LogClaw** - structured log events (port 8000)
* **PacketStrike** - network behavior strikes (port 8001)
* **DNStalon** - DNS behavioral signals (port 8003)

And feeds enriched attack context to:

* **TalonResponse** - incident response terminal

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

# Hard Constraints

* Sigma engine performs detection only
* Correlation engine performs all chain logic
* DuckDB is the single source of truth
* UTC is mandatory everywhere
* Events must remain schema-compliant
* Replay engine uses identical pipeline to live mode

---

# Legal Notice

SIEMulate is a defensive cybersecurity tool.

Only use it on systems you own or are explicitly authorized to monitor.

Unauthorized log collection or monitoring may be illegal in your jurisdiction. The author accepts no liability for misuse.