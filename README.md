# CyberTriage: Autonomous SOC Incident Investigation Engine

CyberTriage is an automated, simulation-only SOC incident triage and investigation system. It bridges real-time security detection telemetry with an AI investigation agent powered by **Google Gemini (`gemini-3.5-flash-lite`)** through the **Switch Core Agent Bridge**.

---

## 🏗️ Architecture

```
[Chat / Mattermost]
        │
        ▼ (Addressed messages, e.g. @cybertriage)
[Switch Core Agent Bridge]
        │
        ▼ (WebSocket JSON Stream: ping/pong, connection_state, message)
[CyberTriage SwitchAgent] (src/agents/switch_agent.py)
        │
        ▼ (Asynchronous delegation)
[GeminiInvestigator] (src/agents/gemini_investigator.py)
        │
        ├──▶ Google GenAI SDK (gemini-3.5-flash-lite)
        │      ▲
        │      │ Multi-turn Function Calling (Tool Requests)
        │      ▼
        ├──▶ Controlled Python Investigation Tools (src/agents/investigation_tools.py)
        │      ├── get_alert(alert_id)
        │      ├── get_alert_evidence(alert_id, limit)
        │      ├── search_events(ip, user, hostname, event_type, limit)
        │      └── list_alerts(severity, status, limit)
        │      │
        │      ▼ (Parameterized queries, safe boundaries)
        ├──▶ [SQLite Evidence Database] (cybertriage.db)
        │
        ▼ (Grounded Markdown Incident Report)
[Switch Outbound POST /agents/{agent_id}/message] ──▶ [Originating Chat Room]
```

If Gemini is unavailable, times out, or lacks an API key, the agent **gracefully falls back** to the deterministic `IncidentAnalyzer`, ensuring continuous, uninterrupted triage capability.

---

## 🔒 Security & Evidence Grounding Principles

1. **Strict Evidence Grounding:** The Gemini AI agent is instructed to state only facts retrieved through tool calls against the SQLite database. Telemetry, event IDs, timestamps, and usernames are never hallucinated.
2. **Explicit Simulation Labeling:** All events, alerts, and report outputs are explicitly labeled as simulated telemetry (`is_simulated: True`).
3. **No Arbitrary SQL or Shell Execution:** The model cannot execute raw SQL or arbitrary shell code. All queries pass through strictly validated, parameterized Python helper functions with input sanitization and limit bounds.
4. **Credential Isolation:** API keys and Switch registration tokens are never logged, committed to version control, or printed in terminal outputs.

---

## 🛠️ Controlled Investigation Tools

| Tool | Purpose | Parameters | Output |
|---|---|---|---|
| `get_alert` | Retrieve alert details by ID | `alert_id` (str) | Alert metadata, rule name, severity, entity details |
| `get_alert_evidence` | Retrieve raw evidence events linked to an alert | `alert_id` (str), `limit` (int, 1-100) | List of verified security events with `is_simulated: True` |
| `search_events` | Correlate telemetry by entity or event type | `ip`, `user`, `hostname`, `event_type`, `limit` (1-50) | Matching historical telemetry events |
| `list_alerts` | Query active alerts by severity or status | `severity` (LOW, MEDIUM, HIGH, CRITICAL), `status`, `limit` | Matching security alerts |

---

## ⚙️ Environment Configuration

Set the following variables in `.env` or your shell environment:

```bash
# Google GenAI API Key (required for AI investigation)
GEMINI_API_KEY="AIzaSy..."

# Gemini Model identifier (defaults to gemini-3.5-flash-lite)
GEMINI_MODEL="gemini-3.5-flash-lite"

# Switch Core Registration Token (required for initial Switch registration)
AGENT_REGISTRATION_TOKEN="swt_..."

# Switch Core URL (optional, defaults to http://localhost:8000)
SWITCH_CORE_URL="http://localhost:8000"
```

---

## 🧪 Running Unit Tests

All 60 unit tests run completely offline with mocked Gemini clients and temporary SQLite databases:

```bash
./venv/bin/python -m unittest discover -s tests -v
```

Test coverage includes:
- `test_investigation_tools.py`: Parameter validation, bounds capping, simulation labeling, error handling, tool dispatch.
- `test_gemini_investigator.py`: Multi-turn function calling, tool execution against SQLite, fallback to rule analyzer on error/timeout/missing key.
- `test_switch_agent.py`: WebSocket protocol, ping/pong heartbeats, position-based resume, frame routing to Gemini investigator, session eviction.
- `test_detection.py`: Brute force, suspicious login, privilege escalation, and unusual access correlation rules.
- `test_database.py`: SQLite WAL mode, schema initialization, parameterized insertions and queries.
- `test_simulator.py`: Synthetic telemetry generation and simulation labeling.

---

## 🚀 Running the End-to-End Investigation Demo

To run a live demonstration of event generation, detection, and Gemini function calling:

```bash
./venv/bin/python demo_investigation.py
```

Sample output excerpt:
```markdown
### 🚨 Incident Investigation Summary & Severity
* **Alert ID:** `alt_f3151b5b658e`
* **Rule Name:** BruteForceLogin
* **Severity:** `HIGH`
* **Status:** `NEW` (Simulation-only telemetry)

### Key Entities
* **Target User:** `admin`
* **Source IP:** `198.51.100.23`
* **Target Host:** `bastion-host`

### Verified Evidence Timeline (Simulation-only)
1. `evt_6ee9cf4a5c06` (2026-11-07T04:47:07.603Z) — auth_failure
2. `evt_ccdc6752287c` (2026-11-07T04:47:09.603Z) — auth_failure
...
```

---

## 📡 Starting the Switch Agent

To start the always-on CyberTriage agent connected to Switch Core:

```bash
./venv/bin/python -m src.main
```
Or directly:
```bash
./venv/bin/python -c "import asyncio; from src.agents.switch_agent import SwitchAgent; asyncio.run(SwitchAgent().run())"
```
