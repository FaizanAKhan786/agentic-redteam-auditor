"""Report generator — produces Markdown vulnerability reports.

Takes findings from an auditor run and generates:
  1. A Markdown report file at reports/report_<timestamp>.md
  2. JSON Lines transcript log at reports/transcripts.jsonl
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auditor.scoring import Finding


# Severity ordering for display
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _severity_sort_key(finding: Finding) -> tuple[int, float]:
    """Sort findings by severity (Critical first) then by score (descending)."""
    return (SEVERITY_ORDER.get(finding.severity, 99), -finding.score)


def _truncate(text: str, max_len: int = 500) -> str:
    """Truncate text for display, preserving meaningful content."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "\n... (truncated)"


def generate_summary_table(findings: list[Finding]) -> str:
    """Generate a Markdown summary table of all findings."""
    if not findings:
        return "_No vulnerabilities found._\n"

    lines = [
        "| # | Vulnerability Class | Severity | Score | Description |",
        "|---|---|---|---|---|",
    ]
    for i, f in enumerate(sorted(findings, key=_severity_sort_key), 1):
        desc_short = f.description[:80] + "..." if len(f.description) > 80 else f.description
        lines.append(f"| {i} | {f.vuln_class} | **{f.severity}** | {f.score} | {desc_short} |")

    return "\n".join(lines) + "\n"


def generate_severity_counts(findings: list[Finding]) -> str:
    """Generate severity count summary."""
    counts = Counter(f.severity for f in findings)
    parts = []
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = counts.get(sev, 0)
        if count > 0:
            emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}[sev]
            parts.append(f"- {emoji} **{sev}**: {count}")
    return "\n".join(parts) if parts else "- No findings"


def generate_finding_detail(finding: Finding, index: int) -> str:
    """Generate detailed Markdown section for a single finding."""
    sections = [
        f"### Finding {index}: {finding.vuln_class}",
        "",
        f"**Severity:** {finding.severity} ({finding.score}/10)  ",
        f"**Confidence:** {finding.confidence:.0%}  ",
        f"**Module:** `{finding.module}`",
        "",
        f"#### Description",
        finding.description,
        "",
        f"#### Reproduction Steps",
        finding.reproduction_steps,
        "",
        f"#### Evidence (Transcript Excerpt)",
        "```",
        _truncate(finding.transcript_excerpt, 800),
        "```",
        "",
        f"#### Suggested Mitigation",
        finding.mitigation,
        "",
        "---",
        "",
    ]
    return "\n".join(sections)


def generate_report(
    findings: list[Finding],
    target_info: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
) -> str:
    """Generate a complete Markdown vulnerability report.

    Args:
        findings: List of Finding objects from the auditor run.
        target_info: Optional dict with target agent metadata.
        output_dir: Directory for the report file. Defaults to 'reports/'.

    Returns:
        The absolute path to the generated report file.
    """
    output_dir = Path(output_dir) if output_dir else Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"report_{timestamp}.md"

    # Sort findings by severity
    sorted_findings = sorted(findings, key=_severity_sort_key)

    # Build report
    sections = [
        "# 🔒 Agentic Red-Team Audit Report",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Total Findings:** {len(findings)}",
        "",
    ]

    # Target info
    if target_info:
        sections.extend([
            "## Target System",
            "",
            f"- **Agent Type:** {target_info.get('agent_type', 'Unknown')}",
            f"- **Model:** {target_info.get('model', 'Unknown')}",
            f"- **Tools:** {', '.join(t.get('name', '?') for t in target_info.get('tools', []))}",
            f"- **RAG:** {target_info.get('rag', {}).get('description', 'None')}",
            "",
        ])

    # Executive summary
    sections.extend([
        "## Executive Summary",
        "",
        generate_severity_counts(sorted_findings),
        "",
    ])

    # Summary table
    sections.extend([
        "## Findings Summary",
        "",
        generate_summary_table(sorted_findings),
        "",
    ])

    # Detailed findings
    if sorted_findings:
        sections.append("## Detailed Findings\n")
        for i, finding in enumerate(sorted_findings, 1):
            sections.append(generate_finding_detail(finding, i))

    # Footer
    sections.extend([
        "## Methodology",
        "",
        "This report was generated by the Agentic Red-Team Auditor, which systematically",
        "tests AI agents for security vulnerabilities using automated attack modules.",
        "Each finding was independently verified by a judge model that evaluates attack",
        "transcripts for signs of successful compromise.",
        "",
        "Severity scores use a CVSS-inspired likelihood × impact matrix calibrated",
        "for AI agent vulnerabilities.",
        "",
        "---",
        f"*Report generated by agentic-redteam-auditor v0.1.0*",
    ])

    report_content = "\n".join(sections)
    report_path.write_text(report_content, encoding="utf-8")

    return str(report_path.resolve())


def log_transcript(
    attempt_data: dict[str, Any],
    verdict_data: dict[str, Any],
    output_dir: str | Path | None = None,
) -> None:
    """Append an attempt + verdict record to the JSON Lines transcript log.

    Args:
        attempt_data: Dict with attempt details (module, payload, description).
        verdict_data: Dict with verdict details (succeeded, confidence, evidence).
        output_dir: Directory for the transcript file. Defaults to 'reports/'.
    """
    output_dir = Path(output_dir) if output_dir else Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    transcript_path = output_dir / "transcripts.jsonl"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attempt": attempt_data,
        "verdict": verdict_data,
    }

    with open(transcript_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
