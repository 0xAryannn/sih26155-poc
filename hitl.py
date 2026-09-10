"""
Minimal Human-in-the-Loop (HITL) layer for unknown configuration syntax.

Team 3 responsibility:
    Parser -> unknown commands -> HITL review -> Team 2 handoff

This module does NOT perform compliance checks or scoring.
It stores only command text, status, and optional notes.
"""

import json
import os
from typing import Any, Dict, List, Optional


DEFAULT_LEARNED_PATH = "learned.json"

VALID_STATUSES = {
    "approved",
    "rejected",
    "needs_review",
}


def load_knowledge_base(path: str = DEFAULT_LEARNED_PATH) -> Dict[str, Any]:
    """Load the HITL knowledge base from disk."""
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

    except (json.JSONDecodeError, OSError):
        pass

    return {}


def save_knowledge_base(
    data: Dict[str, Any],
    path: str = DEFAULT_LEARNED_PATH,
) -> None:
    """Save the HITL knowledge base to disk."""
    parent = os.path.dirname(path)

    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def record_decision(
    command: str,
    status: str,
    note: Optional[str] = None,
    path: str = DEFAULT_LEARNED_PATH,
) -> Dict[str, Any]:
    """
    Record a human decision for an unknown command.

    command:
        Exact configuration command.

    status:
        approved, rejected, or needs_review.

    note:
        Optional human explanation.
    """
    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid HITL status: {status}. "
            f"Expected one of {sorted(VALID_STATUSES)}"
        )

    command = command.strip()

    if not command:
        raise ValueError("Command cannot be empty.")

    data = load_knowledge_base(path)

    # Keep HITL decisions isolated from other learned data.
    hitl = data.setdefault("hitl", {})
    decisions = hitl.setdefault("decisions", {})

    entry: Dict[str, Any] = {
        "status": status,
    }

    if note:
        entry["note"] = note

    decisions[command] = entry

    save_knowledge_base(data, path)

    return entry


def get_decision(
    command: str,
    path: str = DEFAULT_LEARNED_PATH,
) -> Optional[Dict[str, Any]]:
    """Return the existing HITL decision for a command, if any."""
    data = load_knowledge_base(path)

    decisions = (
        data.get("hitl", {})
        .get("decisions", {})
    )

    decision = decisions.get(command.strip())

    if isinstance(decision, dict):
        return decision

    return None


def apply_hitl_status(
    unknown_command: Dict[str, Any],
    path: str = DEFAULT_LEARNED_PATH,
) -> Dict[str, Any]:
    """
    Add the current HITL review status to one unknown command.

    The original command information is preserved.
    """
    command = str(
        unknown_command.get("command", "")
    ).strip()

    result = dict(unknown_command)

    decision = get_decision(command, path)

    if decision:
        result["hitl_status"] = decision.get(
            "status",
            "needs_review",
        )

        if decision.get("note"):
            result["hitl_note"] = decision["note"]
    else:
        result["hitl_status"] = "needs_review"

    return result


def receive_unknown_commands(
    unknown_commands: List[Dict[str, Any]],
    path: str = DEFAULT_LEARNED_PATH,
) -> List[Dict[str, Any]]:
    """
    Parser -> HITL handoff.

    Takes unknown commands produced by the vendor parser and
    attaches their current HITL status.

    This function does NOT make a decision automatically.
    """
    return [
        apply_hitl_status(command, path)
        for command in unknown_commands
    ]


def get_pending_review(
    unknown_commands: List[Dict[str, Any]],
    path: str = DEFAULT_LEARNED_PATH,
) -> List[Dict[str, Any]]:
    """Return commands that still need human review."""
    commands = receive_unknown_commands(
        unknown_commands,
        path,
    )

    return [
        command
        for command in commands
        if command.get("hitl_status") == "needs_review"
    ]


def summarize(
    unknown_commands: List[Dict[str, Any]],
    path: str = DEFAULT_LEARNED_PATH,
) -> Dict[str, int]:
    """Return a simple HITL status summary."""
    commands = receive_unknown_commands(
        unknown_commands,
        path,
    )

    summary = {
        "total": len(commands),
        "approved": 0,
        "rejected": 0,
        "needs_review": 0,
    }

    for command in commands:
        status = command.get(
            "hitl_status",
            "needs_review",
        )

        if status in summary:
            summary[status] += 1

    return summary