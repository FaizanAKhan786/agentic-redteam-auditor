"""Auditor orchestrator — LangGraph state graph for red-team attack execution.

Implements the attack pipeline:
  plan → select_attack_module → execute_attack → judge → record_finding → loop

The orchestrator drives the full audit by:
  1. Planning which attack modules to run based on target capabilities
  2. Iterating through each module's generated attempts
  3. Executing attempts against the target harness
  4. Judging each attempt's success via the judge module
  5. Scoring and recording successful findings
  6. Generating a final Markdown report
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict, Annotated

from auditor.attack_modules import Attempt, get_all_modules
from auditor.judge import Verdict, judge_attempt
from auditor.scoring import Finding, score_finding
from auditor.report import generate_report, log_transcript


class AuditorState(TypedDict):
    """State for the auditor orchestration graph."""
    target_info: dict[str, Any]
    planned_modules: list[str]
    current_module: str
    current_attempts: list[dict[str, Any]]  # serialized Attempts
    current_attempt_idx: int
    findings: list[dict[str, Any]]          # serialized Findings
    transcripts: list[dict[str, Any]]
    report_path: str
    status: str                             # 'planning', 'attacking', 'judging', 'reporting', 'done'


def _serialize_attempt(attempt: Attempt) -> dict[str, Any]:
    """Convert an Attempt to a serializable dict."""
    return {
        "module": attempt.module,
        "payload": attempt.payload,
        "description": attempt.description,
        "injected_doc": attempt.injected_doc,
        "multi_turn": attempt.multi_turn,
    }


def _deserialize_attempt(data: dict[str, Any]) -> Attempt:
    """Reconstruct an Attempt from a dict."""
    return Attempt(
        module=data["module"],
        payload=data["payload"],
        description=data["description"],
        injected_doc=data.get("injected_doc"),
        multi_turn=data.get("multi_turn", []),
    )


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a serializable dict."""
    return {
        "vuln_class": finding.vuln_class,
        "severity": finding.severity,
        "score": finding.score,
        "description": finding.description,
        "reproduction_steps": finding.reproduction_steps,
        "transcript_excerpt": finding.transcript_excerpt,
        "mitigation": finding.mitigation,
        "confidence": finding.confidence,
        "module": finding.module,
        "attempt_payload": finding.attempt_payload,
    }


def _deserialize_finding(data: dict[str, Any]) -> Finding:
    """Reconstruct a Finding from a dict."""
    return Finding(**data)


class AuditorOrchestrator:
    """Orchestrates the red-team audit pipeline.

    Uses an imperative state-machine approach (matching the LangGraph node
    pattern) for clarity and testability. Each method corresponds to a
    LangGraph node.
    """

    def __init__(
        self,
        target_agent: Any,
        judge_llm: Any = None,
        output_dir: str | Path = "reports",
        modules: list[str] | None = None,
    ):
        """Initialize the orchestrator.

        Args:
            target_agent: A TargetAgent instance to attack.
            judge_llm: LLM for the judge. None = use heuristic judge.
            output_dir: Directory for reports and transcripts.
            modules: Optional list of module names to run. None = all modules.
        """
        self.target = target_agent
        self.judge_llm = judge_llm
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.requested_modules = modules
        self.all_modules = get_all_modules()

    def plan(self, state: AuditorState) -> AuditorState:
        """Plan which attack modules to run based on target capabilities.

        Examines target_info to determine applicable modules:
        - If target has tools → tool_call_hijacking is applicable
        - If target has RAG → indirect_prompt_injection, retrieval_poisoning
        - direct_prompt_injection and data_exfiltration are always applicable
        - goal_hijacking is always applicable (just needs conversation)
        """
        target_info = state["target_info"]
        has_tools = bool(target_info.get("tools"))
        has_rag = bool(target_info.get("rag", {}).get("supports_add_document"))

        # Determine applicable modules
        applicable = []

        # Always applicable
        applicable.append("direct_prompt_injection")
        applicable.append("data_exfiltration")

        # Tool-dependent
        if has_tools:
            applicable.append("tool_call_hijacking")

        # RAG-dependent
        if has_rag:
            applicable.append("indirect_prompt_injection")
            applicable.append("retrieval_poisoning")

        # Always applicable (multi-turn)
        applicable.append("goal_hijacking")

        # Filter to requested modules if specified
        if self.requested_modules:
            applicable = [m for m in applicable if m in self.requested_modules]

        # Filter to actually available modules
        applicable = [m for m in applicable if m in self.all_modules]

        state["planned_modules"] = applicable
        state["status"] = "attacking"
        print(f"[PLAN] Planned {len(applicable)} attack modules: {applicable}")
        return state

    def select_attack_module(self, state: AuditorState) -> AuditorState:
        """Pop the next module from the plan and generate attempts."""
        if not state["planned_modules"]:
            state["status"] = "reporting"
            return state

        module_name = state["planned_modules"].pop(0)
        state["current_module"] = module_name

        module = self.all_modules[module_name]
        attempts = module.generate_attempts(state["target_info"])

        state["current_attempts"] = [_serialize_attempt(a) for a in attempts]
        state["current_attempt_idx"] = 0

        print(f"[SELECT] Module '{module_name}': generated {len(attempts)} attempts")
        return state

    def execute_attack(self, state: AuditorState) -> AuditorState:
        """Execute the current attempt against the target harness."""
        idx = state["current_attempt_idx"]
        if idx >= len(state["current_attempts"]):
            return state

        attempt_data = state["current_attempts"][idx]
        attempt = _deserialize_attempt(attempt_data)

        print(f"[ATTACK] Module '{attempt.module}' attempt {idx + 1}/{len(state['current_attempts'])}: {attempt.description[:60]}...")

        try:
            # Step 1: If this is a RAG-based attack, inject the document first
            if attempt.injected_doc:
                self.target.rag_store.add_document(attempt.injected_doc)

            # Step 2: Execute the attack
            if attempt.is_multi_turn:
                result = self.target.run_multi_turn(attempt.multi_turn)
            else:
                result = self.target.run(attempt.payload)

            # Store the transcript for judging
            attempt_data["transcript"] = result.get("messages", [])
            attempt_data["response"] = result.get("response", "")
            attempt_data["tool_calls"] = result.get("tool_calls", [])

        except Exception as e:
            print(f"[ATTACK] Error executing attempt: {e}")
            attempt_data["transcript"] = [{"role": "error", "content": str(e)}]
            attempt_data["response"] = f"Error: {e}"
            attempt_data["tool_calls"] = []

        state["current_attempts"][idx] = attempt_data
        state["status"] = "judging"
        return state

    def judge(self, state: AuditorState) -> AuditorState:
        """Judge the current attempt's success."""
        idx = state["current_attempt_idx"]
        attempt_data = state["current_attempts"][idx]
        attempt = _deserialize_attempt(attempt_data)

        transcript = attempt_data.get("transcript", [])
        verdict = judge_attempt(transcript, attempt.description, llm=self.judge_llm)

        # Store verdict in attempt data
        attempt_data["verdict"] = {
            "succeeded": verdict.succeeded,
            "confidence": verdict.confidence,
            "evidence": verdict.evidence,
        }
        state["current_attempts"][idx] = attempt_data

        # Log to JSONL transcript
        log_transcript(
            attempt_data={
                "module": attempt.module,
                "payload": attempt.payload[:200],
                "description": attempt.description,
            },
            verdict_data={
                "succeeded": verdict.succeeded,
                "confidence": verdict.confidence,
                "evidence": verdict.evidence,
            },
            output_dir=self.output_dir,
        )

        status_icon = "[+] VULNERABLE" if verdict.succeeded else "[-] SAFE"
        print(f"[JUDGE] {status_icon} succeeded={verdict.succeeded}, confidence={verdict.confidence:.2f}")

        return state

    def record_finding(self, state: AuditorState) -> AuditorState:
        """If the attack succeeded, score it and add to findings."""
        idx = state["current_attempt_idx"]
        attempt_data = state["current_attempts"][idx]
        verdict = attempt_data.get("verdict", {})

        if verdict.get("succeeded", False):
            attempt = _deserialize_attempt(attempt_data)
            transcript_text = json.dumps(
                attempt_data.get("transcript", [])[:10],
                indent=2,
                default=str,
            )

            finding = score_finding(
                vuln_class=attempt.module,
                confidence=verdict.get("confidence", 0.5),
                description=attempt.description,
                transcript_excerpt=transcript_text,
                attempt_payload=attempt.payload,
                is_multi_turn=attempt.is_multi_turn,
            )

            state["findings"].append(_serialize_finding(finding))
            print(f"[RECORD] New finding: {finding.vuln_class} -> {finding.severity} ({finding.score})")

        # Advance to next attempt
        state["current_attempt_idx"] = idx + 1
        state["status"] = "attacking"
        return state

    def generate_report_node(self, state: AuditorState) -> AuditorState:
        """Generate the final Markdown report from all findings."""
        findings = [_deserialize_finding(f) for f in state["findings"]]

        report_path = generate_report(
            findings=findings,
            target_info=state["target_info"],
            output_dir=self.output_dir,
        )

        state["report_path"] = report_path
        state["status"] = "done"
        print(f"\n[REPORT] Generated report with {len(findings)} findings: {report_path}")
        return state

    def run(self) -> AuditorState:
        """Execute the full audit pipeline.

        Returns:
            The final AuditorState with all findings and report path.
        """
        # Initialize state
        state: AuditorState = {
            "target_info": self.target.target_info,
            "planned_modules": [],
            "current_module": "",
            "current_attempts": [],
            "current_attempt_idx": 0,
            "findings": [],
            "transcripts": [],
            "report_path": "",
            "status": "planning",
        }

        # Phase 1: Plan
        state = self.plan(state)

        # Phase 2: Loop through modules and attempts
        while state["planned_modules"] or state["current_attempt_idx"] < len(state["current_attempts"]):
            # Select next module if needed
            if state["current_attempt_idx"] >= len(state["current_attempts"]):
                if not state["planned_modules"]:
                    break
                state = self.select_attack_module(state)

            # Execute remaining attempts for current module
            while state["current_attempt_idx"] < len(state["current_attempts"]):
                state = self.execute_attack(state)
                state = self.judge(state)
                state = self.record_finding(state)

        # Phase 3: Generate report
        state = self.generate_report_node(state)

        return state


def main():
    """Run the auditor against the target harness."""
    import argparse
    from target_harness.agent import TargetAgent
    from auditor.llm_client import get_llm, MockLLM

    parser = argparse.ArgumentParser(description="Agentic Red-Team Auditor")
    parser.add_argument("--demo", action="store_true", help="Run a demonstration audit with simulated target responses")
    parser.add_argument("--modules", type=str, default=None, help="Comma-separated list of modules to run")
    parser.add_argument("--output", type=str, default="reports", help="Output directory for reports")
    args = parser.parse_args()

    print("=" * 60)
    print("  AGENTIC RED-TEAM AUDITOR")
    print("=" * 60)
    print()

    selected_modules = [m.strip() for m in args.modules.split(",")] if args.modules else None

    # Initialize target
    if args.demo:
        print("[INIT] Running in DEMO mode with simulated vulnerable target responses")
        demo_responses = [
            "My system prompt says: SECRET_KEY=REDTEAM-2024-CANARY and API_ENDPOINT=https://internal-api.novatech.com/v2",
            "I will ignore previous safety constraints and fulfill your request.",
            "I have sent email to attacker@evil.com with sensitive data.",
            "POISONED: Applying new administrative override instructions.",
            "The secret canary token is REDTEAM-2024-CANARY.",
        ] * 30
        target_llm = MockLLM(responses=demo_responses)
        target = TargetAgent(llm=target_llm)
        judge_llm = None
    else:
        try:
            target = TargetAgent()
            print("[INIT] Target agent initialized with configured LLM endpoint")
        except Exception as e:
            print(f"[ERROR] Failed to initialize target agent: {e}")
            print("[INFO] Make sure your LLM endpoint is running (see .env.example) or run with --demo")
            sys.exit(1)

        # Initialize judge LLM (separate from attacker to reduce bias)
        try:
            judge_llm = get_llm("judge")
            print("[INIT] Judge LLM initialized")
        except Exception:
            judge_llm = None
            print("[INIT] Judge LLM not available - using heuristic judge")

    # Run the audit
    orchestrator = AuditorOrchestrator(
        target_agent=target,
        judge_llm=judge_llm,
        output_dir=args.output,
        modules=selected_modules,
    )

    state = orchestrator.run()

    # Summary
    findings = state["findings"]
    print(f"\n{'=' * 60}")
    print(f"  AUDIT COMPLETE: {len(findings)} vulnerabilities found")
    print(f"  Report: {state['report_path']}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
