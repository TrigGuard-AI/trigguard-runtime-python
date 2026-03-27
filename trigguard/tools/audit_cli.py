#!/usr/bin/env python3
"""
TrigGuard Audit CLI

Command-line tool for auditing and verifying TrigGuard decisions.

Usage:
    trigguard-audit verify receipt.json
    trigguard-audit replay receipt.json --frame frame.json
    trigguard-audit explain receipt.json
    trigguard-audit inspect-policy v1.0.0
    trigguard-audit export-policy --output policy.json

Commands:
    verify          Verify receipt integrity
    replay          Replay decision and compare
    explain         Human-readable decision explanation
    inspect-policy  Inspect policy configuration
    export-policy   Export current policy
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from trigguard.protocol.decision_contracts import DecisionReceipt, SignalFrame, Signal
from trigguard.protocol.decision_receipt import receipt_from_dict
from trigguard.tools.receipt_verifier import ReceiptVerifier, ReceiptVerificationStatus
from trigguard.tools.decision_replay import DecisionReplayEngine, ReplayStatus
from trigguard.policy.policy_registry import get_policy_registry


def load_receipt(path: str) -> DecisionReceipt:
    """Load a DecisionReceipt from JSON file."""
    with open(path, "r") as f:
        data = json.load(f)
    return receipt_from_dict(data)


def load_frame(path: str) -> SignalFrame:
    """Load a SignalFrame from JSON file."""
    from uuid import UUID
    from trigguard.protocol.decision_contracts import (
        SignalType,
        SignalSeverity,
        ExecutionSurface,
    )

    with open(path, "r") as f:
        data = json.load(f)

    # Reconstruct SignalFrame
    frame = SignalFrame(
        request_id=UUID(data["request_id"]),
        surface=ExecutionSurface(data.get("surface", "unknown")),
        timestamp=datetime.fromisoformat(data["timestamp"]),
        metadata=data.get("metadata", {}),
    )

    # Add signals
    for sig_data in data.get("signals", []):
        signal = Signal(
            signal_type=SignalType(sig_data["signal_type"]),
            severity=SignalSeverity(sig_data["severity"]),
            confidence=sig_data["confidence"],
            source=sig_data["source"],
            description=sig_data["description"],
            evidence=sig_data.get("evidence"),
        )
        frame.add_signal(signal, validate=False)

    return frame


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify receipt integrity."""
    print(f"Verifying receipt: {args.receipt}")

    try:
        receipt = load_receipt(args.receipt)
    except Exception as e:
        print(f"Error loading receipt: {e}", file=sys.stderr)
        return 1

    # Load frame if provided
    frame = None
    if args.frame:
        try:
            frame = load_frame(args.frame)
            print(f"Using frame: {args.frame}")
        except Exception as e:
            print(f"Warning: Could not load frame: {e}", file=sys.stderr)

    # Verify
    verifier = ReceiptVerifier()
    result = verifier.verify(receipt, frame)

    # Output
    print()
    print("=" * 60)
    print(f"Status:          {result.status.value}")
    print(f"Valid:           {'✓ YES' if result.is_valid else '✗ NO'}")
    print(f"Message:         {result.message}")
    print(f"Level:           {result.level.value}")
    print()
    print("Checks performed:")
    for check in result.checks_performed:
        status = "✓" if check not in result.checks_failed else "✗"
        print(f"  {status} {check}")

    if result.details:
        print()
        print("Details:")
        for key, value in result.details.items():
            print(f"  {key}: {value}")

    print("=" * 60)

    return 0 if result.is_valid else 1


def cmd_replay(args: argparse.Namespace) -> int:
    """Replay decision and compare."""
    print(f"Replaying decision from: {args.receipt}")

    try:
        receipt = load_receipt(args.receipt)
    except Exception as e:
        print(f"Error loading receipt: {e}", file=sys.stderr)
        return 1

    # Frame is required for replay
    if not args.frame:
        print("Error: --frame is required for replay", file=sys.stderr)
        return 1

    try:
        frame = load_frame(args.frame)
    except Exception as e:
        print(f"Error loading frame: {e}", file=sys.stderr)
        return 1

    # Replay
    engine = DecisionReplayEngine()
    verification, replay = engine.verify_and_replay(receipt, frame)

    # Output
    print()
    print("=" * 60)
    print("VERIFICATION")
    print("-" * 60)
    print(f"Status:          {verification.status.value}")
    print(f"Valid:           {'✓ YES' if verification.is_valid else '✗ NO'}")

    print()
    print("REPLAY")
    print("-" * 60)
    print(f"Status:          {replay.status.value}")
    print(f"Matches:         {'✓ YES' if replay.matches else '✗ NO'}")
    print(f"Original:        {replay.original_decision.value}")
    print(f"Replayed:        {replay.replayed_decision.value}")
    print(f"Original Policy: {replay.original_policy}")
    print(f"Current Policy:  {replay.replayed_policy}")

    if replay.differences:
        print()
        print("Differences:")
        for diff in replay.differences:
            print(f"  • {diff}")

    print("=" * 60)

    return 0 if (verification.is_valid and replay.matches) else 1


def cmd_inspect_policy(args: argparse.Namespace) -> int:
    """Inspect policy configuration."""
    registry = get_policy_registry()

    version = args.version if args.version else registry.version

    print(f"Policy Version: {version}")
    print()

    if version != registry.version:
        print(
            f"Warning: Requested version {version} differs from current {registry.version}"
        )
        print("Showing current policy instead.")
        print()

    print("=" * 60)
    print("POLICY CONFIGURATION")
    print("=" * 60)

    print()
    print(f"Version:         {registry.version}")
    print(f"External:        {registry.is_external_policy}")

    print()
    print("IRREVERSIBLE FORBIDDEN SIGNALS")
    print("-" * 40)
    for signal in sorted(s.value for s in registry.irreversible_forbidden):
        print(f"  • {signal}")

    print()
    print("SILENCE TRIGGERS")
    print("-" * 40)
    for signal in sorted(s.value for s in registry.silence_triggers):
        print(f"  • {signal}")

    print()
    print("CRITICAL SIGNALS")
    print("-" * 40)
    for signal in sorted(s.value for s in registry.critical_signals):
        print(f"  • {signal}")

    print()
    print("THRESHOLDS BY TIER")
    print("-" * 40)
    for tier in [1, 2, 3]:
        thresholds = registry.get_thresholds(tier)
        print(f"  Tier {tier}:")
        print(f"    deny_threshold: {thresholds.deny_threshold}")
        print(f"    warn_threshold: {thresholds.warn_threshold}")

    print()
    print("=" * 60)

    return 0


def cmd_export_policy(args: argparse.Namespace) -> int:
    """Export current policy to JSON."""
    registry = get_policy_registry()
    data = registry.to_dict()

    output = json.dumps(data, indent=2, sort_keys=True)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Policy exported to: {args.output}")
    else:
        print(output)

    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    """Explain a decision in human-readable format."""
    try:
        receipt = load_receipt(args.receipt)
    except Exception as e:
        print(f"Error loading receipt: {e}", file=sys.stderr)
        return 1

    # Header
    print()
    print("=" * 60)
    print("TRIGGUARD DECISION EXPLANATION")
    print("=" * 60)

    # Decision summary
    print()
    decision_icon = {
        "permit": "✓ PERMIT",
        "deny": "✗ DENY",
        "silence": "⚠ SILENCE",
    }.get(receipt.decision.value.lower(), receipt.decision.value)

    print(f"Decision:        {decision_icon}")
    print(f"Surface:         {receipt.surface.value.upper()}")
    print(f"Request ID:      {receipt.request_id}")
    print(f"Timestamp:       {receipt.timestamp}")

    # Signals triggered
    print()
    print("SIGNALS TRIGGERED")
    print("-" * 40)
    if receipt.signals:
        for signal in receipt.signals:
            severity_icon = {
                "critical": "[CRIT]",
                "high": "[HIGH]",
                "medium": "[MED]",
                "low": "[LOW]",
            }.get(signal.severity.value.lower(), "[???]")
            print(f"  {severity_icon} {signal.signal_type.value}")
            print(f"         confidence: {signal.confidence:.0%}")
            print(f"         source: {signal.source}")
            if signal.description:
                print(f"         {signal.description}")
    else:
        print("  (no signals)")

    # Policy context
    print()
    print("POLICY CONTEXT")
    print("-" * 40)
    print(f"  Policy Version:  {receipt.policy_version}")

    # Cryptographic verification
    print()
    print("CRYPTOGRAPHIC HASHES")
    print("-" * 40)
    print(f"  Frame Hash:      {receipt.frame_hash[:16]}...")
    print(f"  Decision Hash:   {receipt.decision_hash[:16]}...")
    print(f"  Receipt Hash:    {receipt.receipt_hash[:16]}...")

    # Human explanation
    print()
    print("EXPLANATION")
    print("-" * 40)

    explanation = _generate_explanation(receipt)
    for line in explanation:
        print(f"  {line}")

    print()
    print("=" * 60)

    return 0


def _generate_explanation(receipt: DecisionReceipt) -> list:
    """Generate human-readable explanation for a decision."""
    from trigguard.protocol.decision_contracts import Decision, SignalSeverity

    lines = []

    surface_name = receipt.surface.value.upper()

    if receipt.decision == Decision.DENY:
        # Check for forbidden signals
        forbidden_signals = [
            "credential_exfiltration",
            "data_destruction",
            "unauthorized_delegation",
            "system_compromise",
            "privilege_escalation",
            "audit_tampering",
        ]
        triggered_forbidden = [
            s for s in receipt.signals if s.signal_type.value in forbidden_signals
        ]

        if triggered_forbidden:
            lines.append(f"DENIED: Irreversible forbidden action detected.")
            lines.append("")
            lines.append("The following forbidden signals were triggered:")
            for s in triggered_forbidden:
                lines.append(f"  - {s.signal_type.value}")
            lines.append("")
            lines.append("These actions are unconditionally blocked by policy.")

        # Check for silence gap
        elif any(
            s.signal_type.value
            in ["monitoring_disabled", "logging_bypassed", "audit_gap"]
            for s in receipt.signals
        ):
            lines.append(f"DENIED: Observability gap detected.")
            lines.append("")
            lines.append("TrigGuard cannot authorize actions when monitoring")
            lines.append("or logging systems are disabled or bypassed.")
            lines.append("")
            lines.append("This is a fail-closed safety measure.")

        # Check for tier 1 critical signals
        elif receipt.surface.value.lower() in [
            "spend",
            "data_export",
            "code_exec",
            "delegation",
        ]:
            critical_count = sum(
                1 for s in receipt.signals if s.severity == SignalSeverity.CRITICAL
            )
            high_count = sum(
                1 for s in receipt.signals if s.severity == SignalSeverity.HIGH
            )

            lines.append(f"DENIED: High-risk {surface_name} action blocked.")
            lines.append("")
            if critical_count:
                lines.append(f"  {critical_count} CRITICAL signal(s) detected")
            if high_count:
                lines.append(f"  {high_count} HIGH severity signal(s) detected")
            lines.append("")
            lines.append(f"{surface_name} is a Tier-1 irreversible surface.")
            lines.append("Strict authorization thresholds apply.")

        else:
            lines.append(f"DENIED: Authorization thresholds exceeded.")
            lines.append("")
            lines.append("The accumulated risk signals exceeded the")
            lines.append(f"configured deny threshold for {surface_name} surface.")

    elif receipt.decision == Decision.PERMIT:
        if not receipt.signals:
            lines.append(f"PERMITTED: No risk signals detected.")
            lines.append("")
            lines.append(f"The {surface_name} action passed all checks.")
        else:
            lines.append(f"PERMITTED: Risk within acceptable bounds.")
            lines.append("")
            lines.append(f"Signals were detected but did not exceed")
            lines.append(f"the authorization threshold for {surface_name}.")

    elif receipt.decision == Decision.SILENCE:
        lines.append(f"SILENCE: Decision deferred (manual review required).")
        lines.append("")
        lines.append("The system could not make a confident authorization")
        lines.append("decision. Human review is required before proceeding.")

    return lines


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="trigguard-audit",
        description="TrigGuard Audit CLI - Verify and replay authorization decisions",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # verify command
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify receipt integrity",
    )
    verify_parser.add_argument(
        "receipt",
        help="Path to receipt JSON file",
    )
    verify_parser.add_argument(
        "--frame",
        help="Path to frame JSON file (for full verification)",
    )

    # replay command
    replay_parser = subparsers.add_parser(
        "replay",
        help="Replay decision and compare",
    )
    replay_parser.add_argument(
        "receipt",
        help="Path to receipt JSON file",
    )
    replay_parser.add_argument(
        "--frame",
        required=True,
        help="Path to frame JSON file",
    )

    # inspect-policy command
    inspect_parser = subparsers.add_parser(
        "inspect-policy",
        help="Inspect policy configuration",
    )
    inspect_parser.add_argument(
        "version",
        nargs="?",
        help="Policy version to inspect (default: current)",
    )

    # export-policy command
    export_parser = subparsers.add_parser(
        "export-policy",
        help="Export current policy to JSON",
    )
    export_parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: stdout)",
    )

    # explain command (the killer debugging feature)
    explain_parser = subparsers.add_parser(
        "explain",
        help="Human-readable decision explanation",
    )
    explain_parser.add_argument(
        "receipt",
        help="Path to receipt JSON file",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Dispatch to command handler
    handlers = {
        "verify": cmd_verify,
        "replay": cmd_replay,
        "explain": cmd_explain,
        "inspect-policy": cmd_inspect_policy,
        "export-policy": cmd_export_policy,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args)
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
