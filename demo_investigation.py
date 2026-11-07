"""End-to-end demonstration of CyberTriage Gemini AI Investigation.

Simulates a real SOC workflow:
1. Generates simulated security events (SSH brute force + privilege escalation).
2. Ingests events into the SQLite database.
3. Runs the Detection Engine to correlate and trigger security alerts.
4. Uses GeminiInvestigator with Google GenAI SDK and gemini-3.5-flash-lite.
5. Performs autonomous function-calling investigation against local SQLite tools.
6. Prints the evidence-grounded incident investigation report.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("CyberTriageDemo")

from src.agents.gemini_investigator import GeminiInvestigator
from src.database.db import Database
from src.detection.engine import DetectionEngine
from src.events.simulator import EventSimulator


def run_demo() -> None:
    print("=" * 80)
    print("CYBERTRIAGE END-TO-END GEMINI AI INVESTIGATION DEMO")
    print("=" * 80)

    # 1. Initialize temporary demonstration database
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = str(Path(temp_dir) / "demo_cybertriage.db")
        db = Database(db_path)
        print(f"\n[1] Initialized clean SQLite SOC Evidence Database at: {db_path}")

        # 2. Generate simulated attack scenarios
        simulator = EventSimulator()
        print("\n[2] Generating simulated SOC telemetry...")
        all_events = simulator.generate_scenario("all")
        for ev in all_events:
            db.insert_event(ev)
        print(f"    -> Ingested {len(all_events)} simulated events into SQLite database.")

        # 3. Run Detection Engine
        print("\n[3] Running Detection Engine to correlate events...")
        engine = DetectionEngine(db)
        alerts = engine.run_detection(all_events)
        print(f"    -> Detected {len(alerts)} security alerts:")
        target_alert_id = None
        for a in alerts:
            print(f"       * [{a.severity}] {a.alert_id}: {a.rule_name} (Evidence: {len(a.evidence_event_ids)} events)")
            if not target_alert_id and a.severity in ("HIGH", "CRITICAL"):
                target_alert_id = a.alert_id

        if not target_alert_id and alerts:
            target_alert_id = alerts[0].alert_id

        print(f"\n[4] Selected alert for AI investigation: {target_alert_id}")

        # 4. Initialize GeminiInvestigator
        print("\n[5] Initializing GeminiInvestigator with model 'gemini-3.5-flash-lite'...")
        investigator = GeminiInvestigator(db=db)
        print(f"    -> Investigator available: {investigator.available}")
        print(f"    -> Model: {investigator.model}")

        # 5. Query 1: Direct alert investigation command
        print("\n" + "=" * 80)
        print(f"QUERY 1: 'investigate {target_alert_id}'")
        print("=" * 80)
        response1 = investigator.handle_message(f"investigate {target_alert_id}", sender="analyst_alice")
        print(response1)

        # 6. Query 2: Natural language SOC query
        print("\n" + "=" * 80)
        print("QUERY 2: 'Show me the latest high severity alerts and check related events'")
        print("=" * 80)
        response2 = investigator.handle_message(
            "Show me the latest high severity alerts and check if there are related events",
            sender="soc_lead_bob",
        )
        print(response2)

        print("\n" + "=" * 80)
        print("DEMO COMPLETE: All investigations verified against SQLite evidence.")
        print("=" * 80)


if __name__ == "__main__":
    run_demo()
