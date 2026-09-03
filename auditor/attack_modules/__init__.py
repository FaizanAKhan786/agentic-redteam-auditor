"""Attack module interface, base types, and registry."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class Attempt:
    """A single attack attempt to execute against the target."""
    module: str                     # e.g. 'direct_prompt_injection'
    payload: str                    # the crafted input to send to the target
    description: str                # human-readable description of this attempt
    injected_doc: str | None = None  # for RAG-based attacks, document to inject first
    multi_turn: list[str] = field(default_factory=list)  # for multi-turn attacks, list of sequential messages

    @property
    def is_multi_turn(self) -> bool:
        return len(self.multi_turn) > 0


@runtime_checkable
class AttackModule(Protocol):
    """Protocol that all attack modules must implement."""
    name: str
    description: str

    def generate_attempts(self, context: dict[str, Any]) -> list[Attempt]:
        """Generate attack attempts given target context.
        
        Args:
            context: Target info dict with keys like 'tools', 'rag', 'agent_type'.
        
        Returns:
            List of Attempt objects to execute.
        """
        ...


def get_all_modules() -> dict[str, AttackModule]:
    """Return a registry of all available attack modules."""
    from auditor.attack_modules.direct_prompt_injection import DirectPromptInjection
    from auditor.attack_modules.indirect_prompt_injection import IndirectPromptInjection
    from auditor.attack_modules.tool_call_hijacking import ToolCallHijacking
    from auditor.attack_modules.retrieval_poisoning import RetrievalPoisoning
    from auditor.attack_modules.data_exfiltration import DataExfiltration
    from auditor.attack_modules.goal_hijacking import GoalHijacking

    modules = [
        DirectPromptInjection(),
        IndirectPromptInjection(),
        ToolCallHijacking(),
        RetrievalPoisoning(),
        DataExfiltration(),
        GoalHijacking(),
    ]
    return {m.name: m for m in modules}
