# CyberTriage: Autonomous SOC Incident Investigation Engine

> [!IMPORTANT]
> **SIMULATION-ONLY PROTOTYPE**: CyberTriage is an automated, simulation-only SOC incident triage and investigation prototype developed for hackathon demonstration and security research. It operates exclusively on synthetic telemetry in local SQLite databases. It is **not production-ready** and should never be connected to live enterprise infrastructure or real production SIEMs without independent security audits and hardening.

CyberTriage bridges real-time security detection telemetry with an AI investigation agent powered by **Google Gemini (`gemini-3.5-flash-lite`)** through the **Switch Core Agent Bridge** and **Mattermost**.

> [!TIP]
> - **Automated Setup Helper**: Run [`./setup.sh`](setup.sh) to quickly create your virtual environment and prepare dependencies.
> - **Comprehensive Evaluation Guide**: Consult [`RUN_GUIDE.md`](RUN_GUIDE.md) for detailed walkthroughs, verification steps, and troubleshooting.

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
4. **Credential Isolation:** API keys and Switch registration tokens are never logged, committed to version control, or printed in terminal outputs. Users must provide their own API keys and tokens; maintainer credentials are never shared.

---

## 🛠️ Controlled Investigation Tools

| Tool | Purpose | Parameters | Output |
|---|---|---|---|
| `get_alert` | Retrieve alert details by ID | `alert_id` (str) | Alert metadata, rule name, severity, entity details |
| `get_alert_evidence` | Retrieve raw evidence events linked to an alert | `alert_id` (str), `limit` (int, 1-100) | List of verified security events with `is_simulated: True` |
| `search_events` | Correlate telemetry by entity or event type | `ip`, `user`, `hostname`, `event_type`, `limit` (1-50) | Matching historical telemetry events |
| `list_alerts` | Query active alerts by severity or status | `severity` (LOW, MEDIUM, HIGH, CRITICAL), `status`, `limit` | Matching security alerts |

---

## 🚦 Execution Paths

Choose one of two evaluation paths based on your testing environment:
- **[PATH 1: Quick Local Evaluation](#path-1-quick-local-evaluation-recommended-for-judges)**: Evaluate immediately on your local machine with standard Python. Does **not** require Docker, Switch Core, or Mattermost.
- **[PATH 2: Full Switch + Mattermost Integration](#path-2-full-switch--mattermost-integration)**: Run the always-on agent connected to live Switch Core and Mattermost infrastructure.

---

## PATH 1: Quick Local Evaluation (Recommended for Judges)

This path allows hackathon judges and external developers to evaluate CyberTriage's event generation, rule-based detection engine, and Gemini AI investigation in minutes without running any external containers or messaging bridges.

> **Fast Track**: You can run [`./setup.sh`](setup.sh) to automate environment creation and dependency installation, or follow the step-by-step instructions below.

### 1. Clone the Repository
```bash
git clone https://github.com/silentdisk/CyberTriage.git
cd CyberTriage
```

### 2. Set Up Python Virtual Environment
Requires Python 3.10+ (Python 3.11+ recommended):
```bash
python3 -m venv venv
source venv/bin/activate
# On Windows:
# venv\Scripts\activate
```

### 3. Install Dependencies
Ensure the virtual environment is activated before installing dependencies:
```bash
python -m pip install -r requirements.txt pytest
```

### 4. Configure Your Gemini API Key
Initialize `.env` from the provided template:
```bash
cp .env.example .env
```

Edit `.env` with your own credentials:
```bash
# In .env
GEMINI_API_KEY="your_gemini_api_key_here"
GEMINI_MODEL="gemini-3.5-flash-lite"
```

> [!NOTE]
> **API Key & Fallback Notice:**
> - Users must supply their own Google Gemini API key. Never share, commit, or request maintainer credentials.
> - If `GEMINI_API_KEY` is omitted or unconfigured, CyberTriage will activate its deterministic rule-based fallback analyzer (`IncidentAnalyzer`). While this verifies that the fallback mechanism operates safely and predictably, it **does not demonstrate live Gemini AI multi-turn function calling**. A valid `GEMINI_API_KEY` with internet connectivity is required to observe autonomous function calling.

### 5. Run the Offline Unit Test Suite
Distinguish offline tests from live API testing: all unit tests run **completely offline** using mock Gemini clients and isolated temporary SQLite databases. No live API calls or network requests are made.

Run the test suite using `pytest`:
```bash
python -m pytest -q
```
Or using Python's standard `unittest` runner:
```bash
python -m unittest discover -s tests -v
```

> [!TIP]
> The test suite currently includes 84 passing tests covering the database layer, detection engine, event simulator, controlled investigation tools, Gemini function-calling loop, and Switch WebSocket protocol. Always run the tests directly to confirm results on your environment rather than assuming an exact count.

### 6. Run the End-to-End Investigation Demo
Run the standalone end-to-end demonstration script:
```bash
python demo_investigation.py
```

**What this demo does:**
1. **Creates a temporary SQLite database:** Generates a clean, isolated database in a temporary directory (e.g., `/tmp/...`).
2. **Generates simulated telemetry:** Emits synthetic SOC events (SSH brute-force attempts, suspicious logins, and privilege escalation).
3. **Executes detection rules:** Evaluates events and creates correlated security alerts (e.g., `BruteForceLogin`, `SuspiciousLoginPattern`).
4. **Initializes GeminiInvestigator:** Loads the `gemini-3.5-flash-lite` model with tool declarations.
5. **Performs autonomous investigation:** Conducts multi-turn function calling against local SQLite tools (`get_alert`, `get_alert_evidence`, `search_events`, `list_alerts`).
6. **Renders incident reports:** Prints structured, evidence-grounded Markdown triage reports with cited Event IDs.

*This path requires zero Docker setup, zero external services, and zero chat infrastructure.*

---

## PATH 2: Full Switch + Mattermost Integration

This path runs CyberTriage as an always-on background agent integrated with **Switch Core Agent Bridge** and **Mattermost**.

### Prerequisites
- **Docker & Docker Compose** (to host your Switch Core and Mattermost infrastructure).
- **Outbound Internet Access** (for Gemini API calls).
- **Your Own Credentials:** You must supply your own Google Gemini API key, your own Switch Core URL, and your own Switch registration token.

### 1. External Infrastructure Setup (Switch Core & Mattermost)
CyberTriage connects to Switch Core via WebSocket and REST APIs, but **does not bundle or manage external Switch or Mattermost server deployments**.

Users must run their own infrastructure:
1. Deploy **Mattermost** (e.g., via Docker Compose).
2. Deploy **Switch Core** with the Mattermost bridge adapter enabled.
3. Configure your Mattermost bot credentials in Switch Core.

> [!NOTE]
> Refer to the official [Switch Documentation](https://github.com/sandbox-quantum/switch) for exact Docker Compose templates, bridge adapter settings, and server provisioning steps.

### 2. Configure Environment Variables
Set your credentials in your `.env` file (or export them in your shell):
```bash
# Google Gemini configuration (Your own key)
GEMINI_API_KEY="your_gemini_api_key_here"
GEMINI_MODEL="gemini-3.5-flash-lite"

# Registration Token (Provided by your Switch Core administrator)
AGENT_REGISTRATION_TOKEN="your_switch_registration_token_here"
```

*(Note: The Switch Core base URL is configured at runtime via the `--switch-url` CLI argument, defaulting to `http://localhost:8000`).*

> [!IMPORTANT]
> - Never publish or commit your `.env` or credentials files.
> - On initial startup without an existing `.switch_credentials.json`, CyberTriage automatically registers itself with Switch Core using `AGENT_REGISTRATION_TOKEN` via `POST /agents` and persists its assigned `agent_id` and `agent_api_key` to `.switch_credentials.json`.
> - Once registered, `.switch_credentials.json` is reused for persistent sessions and stream resumption.

### 3. Start the Switch Agent
Start the always-on CyberTriage agent connected to Switch Core using the verified CLI command:

```bash
python src/main.py switch-agent --switch-url http://localhost:8000
```

*(Optional arguments: `--credentials <path>` to specify a custom credentials file path, or `--db <path>` placed before the subcommand for a custom SQLite database path, e.g. `python src/main.py --db custom.db switch-agent ...`).*

Upon startup, CyberTriage will:
1. Verify or establish registration with Switch Core.
2. Establish a persistent WebSocket stream with Switch Core (`ws://localhost:8000/agents/<agent_id>/connection/ws?filter=addressed`).
3. Handle bi-directional heartbeats (`ping`/`pong` with sequence cursors).
4. Listen for addressed incoming messages from Mattermost channels.

### 4. Test Commands in Mattermost
Once the agent is connected and invited to a Mattermost channel, mention `@cybertriage` to initiate investigations:

- **Get Help & Usage:**
  ```text
  @cybertriage help
  ```
- **List High-Severity Alerts:**
  ```text
  @cybertriage list HIGH alerts
  ```
- **Investigate a Specific Alert:**
  ```text
  @cybertriage investigate <alert_id>
  ```
  *(Example: `@cybertriage investigate alt_008918e25558`)*

When an investigation command is received:
1. Switch Core routes the message frame to CyberTriage over the WebSocket stream.
2. CyberTriage invokes `GeminiInvestigator` (or the deterministic fallback if Gemini is unconfigured).
3. The investigator autonomously queries the local SQLite evidence database through parameterized tools.
4. CyberTriage formats an evidence-grounded Markdown triage report and sends it back to the Mattermost room via `POST /agents/{agent_id}/message`.

---

## 💻 Standalone CLI Utilities

For manual inspection of local telemetry and alerts, CyberTriage provides standalone CLI utilities:

```bash
# Generate simulated security events
python src/main.py simulate --scenario brute_force

# Run rule-based detection engine
python src/main.py detect

# List active alerts
python src/main.py alerts --limit 10

# Inspect evidence and triage recommendations for an alert
python src/main.py investigate <alert_id>

# Clear local database
python src/main.py clear-db
```

---

## 📚 Documentation Reference

- **[Operator & Evaluation Guide](RUN_GUIDE.md)**: In-depth execution guide, dual-mode AI vs. fallback comparison, troubleshooting, and verification walkthrough.
- **[System Architecture](ARCHITECTURE.md)**: Architectural specifications, event schemas, SQLite WAL design, and sequence diagrams.
- **[Setup Helper](setup.sh)**: Executable environment bootstrapping script for rapid local onboarding.
