"""Command-line interface for CyberTriage SOC incident triage system."""

import argparse
import json
import logging
import sys
from typing import Optional

from src.database.db import DEFAULT_DB_PATH, Database
from src.detection.engine import DetectionEngine
from src.events.simulator import EventSimulator

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cybertriage")


def format_severity(severity: str) -> str:
    """Add color / icon formatting to severity labels."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return f"\033[91m[CRITICAL]\033[0m"
    elif sev == "HIGH":
        return f"\033[93m[HIGH]\033[0m"
    elif sev == "MEDIUM":
        return f"\033[94m[MEDIUM]\033[0m"
    else:
        return f"\033[92m[LOW]\033[0m"


def handle_simulate(args: argparse.Namespace) -> None:
    """Handle the 'simulate' subcommand."""
    db = Database(args.db)
    sim = EventSimulator()

    print(f"\n[*] Generating simulated security events (Scenario: '{args.scenario}')...")
    if args.scenario == "benign" and args.count:
        events = sim.generate_benign(count=args.count)
    else:
        events = sim.generate_scenario(args.scenario)

    inserted = db.insert_events(events)
    print(f"[+] Successfully generated and stored {inserted} simulated events in '{args.db}'.")

    # Sample summary
    print("\nRecent generated events sample:")
    print("-" * 80)
    print(f"{'Event ID':<16} | {'Timestamp':<24} | {'Type':<18} | {'User':<10} | {'IP':<15}")
    print("-" * 80)
    for e in events[:8]:
        print(f"{e.event_id:<16} | {e.timestamp[:23]:<24} | {e.event_type:<18} | {e.user:<10} | {e.src_ip:<15}")
    if len(events) > 8:
        print(f"... and {len(events) - 8} more events.")
    print("-" * 80)


def handle_detect(args: argparse.Namespace) -> None:
    """Handle the 'detect' subcommand."""
    db = Database(args.db)
    engine = DetectionEngine(db)

    print(f"\n[*] Running detection rules against stored events in '{args.db}'...")
    new_alerts = engine.run_detection()

    if not new_alerts:
        print("[+] Detection complete. No new alerts generated (or all already detected).")
        return

    print(f"\n[!] Generated {len(new_alerts)} new security alert(s):")
    print("=" * 90)
    print(f"{'Alert ID':<16} | {'Severity':<18} | {'Rule':<24} | {'Title':<28}")
    print("-" * 90)
    for a in new_alerts:
        sev = format_severity(a.severity)
        print(f"{a.alert_id:<16} | {sev:<18} | {a.rule_name:<24} | {a.title[:28]:<28}")
    print("=" * 90)
    print("\nTip: Run 'cybertriage investigate <ALERT_ID>' to inspect evidence and triage.")


def handle_alerts(args: argparse.Namespace) -> None:
    """Handle the 'alerts' subcommand."""
    db = Database(args.db)
    alerts = db.get_alerts(limit=args.limit, severity=args.severity)

    if not alerts:
        print("\n[+] No alerts found in database.")
        return

    print(f"\n[*] Displaying {len(alerts)} alert(s) from '{args.db}':")
    print("=" * 105)
    print(f"{'Alert ID':<16} | {'Severity':<18} | {'Timestamp':<20} | {'Rule':<22} | {'Entity':<18}")
    print("-" * 105)
    for a in alerts:
        entity = f"{a.entity_user or '-'}@{a.entity_ip or '-'}"
        sev = format_severity(a.severity)
        print(f"{a.alert_id:<16} | {sev:<18} | {a.timestamp[:19]:<20} | {a.rule_name[:22]:<22} | {entity:<18}")
    print("=" * 105)
    print("\nTip: Run 'cybertriage investigate <ALERT_ID>' to see linked evidence events.")


def handle_investigate(args: argparse.Namespace) -> None:
    """Handle the 'investigate' subcommand."""
    db = Database(args.db)
    alert = db.get_alert(args.alert_id)

    if not alert:
        print(f"\n[-] Error: Alert '{args.alert_id}' not found in database.")
        sys.exit(1)

    print("\n" + "=" * 80)
    print(f"  CYBERTRIAGE INCIDENT INVESTIGATION REPORT: {alert.alert_id}")
    print("=" * 80)
    print(f"Title:         {alert.title}")
    print(f"Severity:      {format_severity(alert.severity)}")
    print(f"Rule:          {alert.rule_name}")
    print(f"Detected At:   {alert.timestamp}")
    print(f"Target User:   {alert.entity_user or 'N/A'}")
    print(f"Source IP:     {alert.entity_ip or 'N/A'}")
    print(f"Target Host:   {alert.entity_host or 'N/A'}")
    print(f"Current Status:{alert.status}")
    print("-" * 80)
    print(f"Summary Description:\n{alert.description}")
    print("-" * 80)

    # Fetch and present exact evidence events
    print(f"Linked Evidence Events ({len(alert.evidence_event_ids)} event(s)):")
    evidence_events = db.get_events_by_ids(alert.evidence_event_ids)

    if not evidence_events:
        print("  [-] No evidence event records found matching IDs.")
    else:
        for idx, ev in enumerate(evidence_events, 1):
            print(f"\n  [Evidence #{idx}] ID: {ev.event_id} | Time: {ev.timestamp} | Type: {ev.event_type}")
            print(f"    Action: {ev.action} | Host: {ev.hostname} | User: {ev.user} | IP: {ev.src_ip}")
            print(f"    Details: {json.dumps(ev.details, indent=6).strip()}")

    print("\n" + "-" * 80)
    print("Triage Recommendation:")
    if alert.severity in ("CRITICAL", "HIGH"):
        if "BruteForce" in alert.rule_name:
            print(f"  • Immediate Action: Temporarily block source IP '{alert.entity_ip}' at perimeter firewall.")
            print(f"  • Verify whether any subsequent successful authentication occurred for '{alert.entity_user}'.")
        elif "PrivilegeEscalation" in alert.rule_name:
            print(f"  • Immediate Action: Isolate host '{alert.entity_host}' and terminate unauthorized session.")
            print(f"  • Audit user '{alert.entity_user}' account permissions and inspect `/etc/sudoers`.")
        elif "SuspiciousLogin" in alert.rule_name:
            print(f"  • Immediate Action: Revoke active session tokens for user '{alert.entity_user}'.")
            print(f"  • Contact user or verify if IP '{alert.entity_ip}' corresponds to authorized VPN/cloud egress.")
    else:
        print("  • Action: Review telemetry and correlate with host baseline activity.")
    print("=" * 80 + "\n")


def handle_demo(args: argparse.Namespace) -> None:
    """Run an end-to-end incident simulation, detection, and investigation demo."""
    db = Database(args.db)
    print("\n" + "#" * 80)
    print("  CYBERTRIAGE END-TO-END DEMO EXECUTION")
    print("#" * 80)

    # 1. Reset / Prepare
    scenario = args.scenario or "brute_force"
    print(f"\n[Step 1] Generating simulated security incident (Scenario: '{scenario}')...")
    sim = EventSimulator()
    events = sim.generate_scenario(scenario)
    db.insert_events(events)
    print(f"[+] Stored {len(events)} synthetic events into '{args.db}'.")

    # 2. Run Detection
    print("\n[Step 2] Running rule-based detection engine...")
    engine = DetectionEngine(db)
    alerts = engine.run_detection()

    if not alerts:
        # Check if alerts already existed
        alerts = db.get_alerts(limit=5)

    if not alerts:
        print("[-] No alerts produced. Check scenario configuration.")
        return

    # 3. Investigate top alert
    top_alert = alerts[0]
    print(f"\n[Step 3] Investigating generated alert: '{top_alert.alert_id}'...")
    args.alert_id = top_alert.alert_id
    handle_investigate(args)


def handle_clear_db(args: argparse.Namespace) -> None:
    """Handle database reset."""
    db = Database(args.db)
    db.clear_database()
    print(f"[+] Successfully cleared all events and alerts from '{args.db}'.")


def handle_switch_agent(args: argparse.Namespace) -> None:
    """Handle the 'switch-agent' subcommand to start the Switch Agent Bridge client."""
    import asyncio
    from src.agents.switch_agent import SwitchAgent

    db = Database(args.db)
    agent = SwitchAgent(
        switch_url=args.switch_url,
        db=db,
        credentials_path=args.credentials,
    )

    print("\n" + "=" * 80)
    print("  CYBERTRIAGE SWITCH CORE AGENT BRIDGE")
    print("=" * 80)
    print(f"Switch Core URL:  {args.switch_url}")
    print(f"Database:         {args.db}")
    print(f"Credentials File: {args.credentials}")
    print("Press Ctrl+C to stop the agent.\n")

    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        print("\n[+] Agent stopped by user.")
    except Exception as e:
        print(f"\n[-] Agent error: {e}")
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="cybertriage",
        description="CyberTriage - Lightweight SOC Incident Detection and Triage System",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database file (default: {DEFAULT_DB_PATH})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Generate simulated security events")
    p_sim.add_argument(
        "--scenario",
        default="all",
        choices=["benign", "brute_force", "privesc", "suspicious_login", "all"],
        help="Simulated incident scenario to generate (default: all)",
    )
    p_sim.add_argument(
        "--count",
        type=int,
        default=15,
        help="Number of events to generate for benign scenario (default: 15)",
    )

    # detect
    subparsers.add_parser("detect", help="Run detection rules against stored events")

    # alerts
    p_alt = subparsers.add_parser("alerts", help="List recent detection alerts")
    p_alt.add_argument("--limit", type=int, default=20, help="Maximum alerts to display")
    p_alt.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Filter alerts by severity",
    )

    # investigate
    p_inv = subparsers.add_parser("investigate", help="Investigate an alert by its ID")
    p_inv.add_argument("alert_id", help="The alert ID (e.g. alt_01a2b3c4...) to investigate")

    # run-demo
    p_demo = subparsers.add_parser("run-demo", help="Run an end-to-end simulation, detection, and investigation demo")
    p_demo.add_argument(
        "--scenario",
        default="brute_force",
        choices=["brute_force", "privesc", "suspicious_login", "all"],
        help="Scenario to run in demo mode (default: brute_force)",
    )

    # clear-db
    subparsers.add_parser("clear-db", help="Clear all stored events and alerts from the database")

    # switch-agent
    p_agent = subparsers.add_parser(
        "switch-agent", help="Start the always-on CyberTriage agent connected to Switch Core"
    )
    p_agent.add_argument(
        "--switch-url",
        default="http://localhost:8000",
        help="Switch Core base URL (default: http://localhost:8000)",
    )
    p_agent.add_argument(
        "--credentials",
        default=".switch_credentials.json",
        help="Path to credentials file (default: .switch_credentials.json)",
    )

    return parser


def main() -> None:
    """Entry point for the CyberTriage CLI."""
    parser = build_parser()
    args = parser.parse_args()

    commands = {
        "simulate": handle_simulate,
        "detect": handle_detect,
        "alerts": handle_alerts,
        "investigate": handle_investigate,
        "run-demo": handle_demo,
        "clear-db": handle_clear_db,
        "switch-agent": handle_switch_agent,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
