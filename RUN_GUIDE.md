# CyberTriage Operator & Evaluation Guide

> [!IMPORTANT]
> **SIMULATION-ONLY PROTOTYPE**: CyberTriage is an automated, simulation-only SOC incident triage and investigation prototype developed for hackathon demonstration and security research. It operates exclusively on synthetic telemetry in local SQLite databases. It is **not production-ready** and should never be connected to live enterprise infrastructure or real production SIEMs without independent security audits and hardening.

This guide provides step-by-step instructions for evaluating CyberTriage in two configurations:
1. **[PATH 1: Quick Local Evaluation](#path-1-quick-local-evaluation-standalone)**: 100% offline-capable, standalone evaluation requiring only standard Python (no Docker, Switch Core, or Mattermost).
2. **[PATH 2: Full Switch + Mattermost Integration](#path-2-full-switch--mattermost-integration)**: Always-on agent connected to live Switch Core and Mattermost messaging infrastructure.

---

## 🚀 Environment Setup

You can set up the environment automatically using the setup helper script, or manually.

### Automated Setup (Recommended)
Run the setup helper script from the repository root:
```bash
chmod +x setup.sh
./setup.sh
```

The script will:
- Check for Python 3 (3.10+) and pip.
- Create a virtual environment in `venv/` if one does not exist.
- Install all required dependencies from `requirements.txt`.
- Copy `.env.example` to `.env` if `.env` does not already exist (preserving existing credentials).

### Manual Setup
Alternatively, set up your virtual environment manually:
```bash
git clone https://github.com/silentdisk/CyberTriage.git
cd CyberTriage

python3 -m venv venv
source venv/bin/activate
# On Windows: venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env
```

---

## 🔑 Gemini API Key & Investigation Modes

CyberTriage features dual-mode investigation to guarantee continuous triage availability:

```
                  ┌───────────────────────────────┐
                  │ Incoming Investigation Query  │
                  └───────────────┬───────────────┘
                                  │
                   Is GEMINI_API_KEY configured?
                                  │
                 ┌────────────────┴────────────────┐
                 ▼ (Yes)                           ▼ (No / Error)
    ┌─────────────────────────┐       ┌─────────────────────────┐
    │   GeminiInvestigator    │       │    IncidentAnalyzer     │
    │  (Autonomous AI Loop)   │       │ (Deterministic Fallback)│
    └────────────┬────────────┘       └────────────┬────────────┘
                 │                                 │
     Multi-turn Tool Calling              Direct Rule Evaluation
  (get_alert, get_alert_evidence,        (Strict regex matching
   search_events, list_alerts)            on 'investigate <id>')
                 │                                 │
                 ▼                                 ▼
   Evidence-Grounded AI Report         Deterministic Evidence Report
```

### 1. Live Gemini AI Function Calling (`GeminiInvestigator`)
- **Engine**: Google GenAI SDK with `gemini-3.5-flash-lite`.
- **Requirements**: Outbound internet access and a valid `GEMINI_API_KEY` set in `.env`.
- **Capabilities**:
  - Autonomous multi-turn reasoning and tool invocation against local SQLite tools (`get_alert`, `get_alert_evidence`, `search_events`, `list_alerts`).
  - Supports conversational queries (e.g., `"Show latest HIGH severity alerts"`, `"Are there failed logins from IP 198.51.100.23?"`).
  - Generates comprehensive Markdown incident triage reports with MITRE classification, key entity summaries, and verified evidence timelines.

### 2. Deterministic Rule-Based Fallback (`IncidentAnalyzer`)
- **Engine**: Pure Python rule-based incident analysis against SQLite evidence.
- **Trigger Conditions**:
  - `GEMINI_API_KEY` is missing or empty.
  - Gemini API timeout, DNS name resolution failure, or network disruption.
  - Multi-turn function calling loop returns empty output.
- **Capabilities**:
  - Strictly parses and executes `investigate <ALERT_ID>` commands.
  - Retrieves alert details and linked raw evidence events directly from the SQLite database.
  - Emits formatted incident investigation reports and actionable SOC triage recommendations.

> [!NOTE]
> **Evaluation Distinction for Judges:**
> Running without a `GEMINI_API_KEY` demonstrates the graceful fallback resiliency of CyberTriage, but **does not demonstrate live Gemini function calling**. To observe autonomous multi-turn tool calling, configure your own `GEMINI_API_KEY` in `.env`.

---

## PATH 1: Quick Local Evaluation (Standalone)

*Requires zero Docker setup, zero external services, and zero chat infrastructure.*

### Step 1: Run the Offline Test Suite
Distinguish offline tests from live API testing: all 84 unit tests run **completely offline** with mocked Gemini clients and isolated temporary SQLite databases.

```bash
# Using pytest
pytest

# Or using standard unittest
python -m unittest discover -s tests -v
```

**Expected Outcome:**
- All 84 tests pass cleanly in ~1 second.
- Verified test modules:
  - `test_database.py`: SQLite schema, WAL mode, parameterized queries.
  - `test_detection.py`: Brute force, suspicious login, privilege escalation, and sensitive resource access rules.
  - `test_gemini_investigator.py`: Multi-turn function calling, tool execution, fallback triggers, logging.
  - `test_investigation_tools.py`: Parameter validation, bounds capping, simulation labeling, error handling.
  - `test_simulator.py`: Synthetic telemetry generation and simulation labeling.
  - `test_switch_agent.py`: WebSocket protocol, ping/pong heartbeats, cursor resume, frame routing.

### Step 2: Run the End-to-End Investigation Demo
Execute the standalone investigation demonstration script:
```bash
python demo_investigation.py
```

**What occurs during the demo:**
1. **Initializes clean temporary SQLite DB**: Creates an isolated database file in `/tmp/.../demo_cybertriage.db`.
2. **Generates synthetic SOC telemetry**: Simulates SSH brute force attempts, suspicious login patterns, and privilege escalation events.
3. **Executes Detection Engine**: Evaluates telemetry against correlation rules and raises 4 security alerts.
4. **Initializes GeminiInvestigator**: Loads `gemini-3.5-flash-lite` and exposes controlled investigation tools.
5. **Performs Investigation Queries**:
   - Query 1: Direct alert investigation command (`investigate <alert_id>`).
   - Query 2: Natural language query (`Show me the latest high severity alerts...`).
6. **Outputs Grounded Report**: Formats evidence-grounded reports with cited Event IDs.

### Step 3: Use Standalone CLI Utilities
You can also run individual detection and investigation commands manually:

```bash
# 1. Generate simulated security events (Scenario: brute_force, privesc, suspicious_login, or all)
python src/main.py simulate --scenario brute_force

# 2. Run detection rules against stored events
python src/main.py detect

# 3. List active alerts generated by the detection engine
python src/main.py alerts --limit 10

# 4. Investigate an alert and retrieve linked evidence
python src/main.py investigate <ALERT_ID>

# 5. Clear local database when finished
python src/main.py clear-db
```

*(Note: To target a custom database, pass `--db <path>` before the subcommand, e.g., `python src/main.py --db my_test.db simulate --scenario brute_force`).*

---

## PATH 2: Full Switch + Mattermost Integration

This path runs CyberTriage as an always-on background agent integrated with **Switch Core Agent Bridge** and **Mattermost**.

### Prerequisites
- **Docker & Docker Compose** (to run Switch Core and Mattermost infrastructure).
- **Outbound Internet Access** (for Gemini API calls).
- **Your Own Credentials**: You must supply your own Google Gemini API key and Switch registration token.

### Step 1: External Infrastructure Setup
CyberTriage connects to Switch Core via WebSocket and REST APIs, but **does not bundle or manage external Switch Core or Mattermost server deployments**.

Users must run their own infrastructure:
1. Deploy **Mattermost** (e.g., via Docker Compose).
2. Deploy **Switch Core** with the Mattermost bridge adapter enabled.
3. Configure your Mattermost bot credentials in Switch Core.

> [!NOTE]
> Refer to the official [Switch Documentation](https://github.com/sandbox-quantum/switch) for exact Docker Compose templates, bridge adapter settings, and server provisioning steps.

### Step 2: Configure Environment Variables
Set your credentials in `.env`:
```bash
# Google Gemini configuration (Your own key)
GEMINI_API_KEY="your_gemini_api_key_here"
GEMINI_MODEL="gemini-3.5-flash-lite"

# Registration Token (Provided by your Switch Core administrator)
AGENT_REGISTRATION_TOKEN="your_switch_registration_token_here"
```

### Step 3: Start the Switch Agent
Start the always-on CyberTriage agent connected to Switch Core:

```bash
python src/main.py switch-agent --switch-url http://localhost:8000
```

*(Optional flags: `--credentials <path>` for custom credentials path, or `--db <path>` placed before the subcommand for custom database).*

**Agent Lifecycle:**
1. **Registration**: On initial startup without `.switch_credentials.json`, the agent registers with Switch Core (`POST /agents`) using `AGENT_REGISTRATION_TOKEN` and saves credentials to `.switch_credentials.json`.
2. **Reconnection**: Subsequent runs load `.switch_credentials.json` directly.
3. **WebSocket Stream**: Connects to `ws://localhost:8000/agents/<agent_id>/connection/ws?filter=addressed`.
4. **Heartbeats**: Responds to `event: ping` frames with sequence cursors (`type: "pong"`).
5. **Frame Dispatch**: Routes incoming addressed messages to `GeminiInvestigator` (or fallback).

### Step 4: Interact via Mattermost
Once the bot is running and invited to a Mattermost channel:

- **Usage help:**
  ```text
  @cybertriage help
  ```
- **List high-severity alerts:**
  ```text
  @cybertriage list HIGH alerts
  ```
- **Investigate a security incident:**
  ```text
  @cybertriage investigate alt_008918e25558
  ```

CyberTriage processes the query, queries the SQLite database using controlled tools, and posts the investigation report back to the channel.

---

## 🔒 Credential Safety & Security Guarantees

1. **User-Supplied Credentials Only**: Maintainer credentials and API keys are never published or shared. Users supply their own keys in `.env`.
2. **Git Isolation**: `.env`, `.switch_credentials.json`, and `*.db` are excluded from version control in `.gitignore`.
3. **No Credential Logging**: Tokens and keys are never printed in console logs or included in error traces.
4. **Safe Query Boundaries**: Investigation tools use parameterized queries and input sanitization (`MAX_ALERT_ID_LENGTH = 128`, regex character checking). Raw SQL and shell execution are strictly forbidden.
5. **Strict Grounding**: The Gemini model is constrained by system instructions to state only facts corroborated by SQLite evidence events.
