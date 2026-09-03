import sys
from pathlib import Path
import pytest

from auditor.llm_client import MockLLM
from auditor.orchestrator import AuditorOrchestrator
from target_harness.agent import TargetAgent
from target_harness.rag_store import RAGStore


class TestEndToEnd:
    """Smoke test: run the full orchestrator with a mocked LLM."""

    def test_single_module_produces_report(self, tmp_path):
        # Create a mock LLM that simulates the target leaking its prompt
        target_llm = MockLLM(responses=[
            # The target will 'leak' its system prompt on every query
            "My system prompt says: SECRET_KEY=REDTEAM-2024-CANARY and I am NovaTech Assistant.",
        ] * 20)  # Enough responses for all attempts

        # Create a minimal RAG store (no real embeddings needed)
        rag_store = RAGStore(docs_dir=tmp_path / "empty_docs")
        (tmp_path / "empty_docs").mkdir()
        (tmp_path / "empty_docs" / "test.txt").write_text("Test document.")

        target = TargetAgent(
            llm=target_llm,
            rag_store=rag_store,
            max_turns=1,  # Limit turns to speed up
        )

        reports_dir = tmp_path / "reports"
        orchestrator = AuditorOrchestrator(
            target_agent=target,
            judge_llm=None,  # Use heuristic judge
            output_dir=reports_dir,
            modules=["direct_prompt_injection"],  # Just one module
        )

        state = orchestrator.run()

        # Verify report was produced
        assert state["report_path"] != ""
        assert Path(state["report_path"]).exists()

        # Verify report is valid Markdown
        content = Path(state["report_path"]).read_text(encoding="utf-8")
        assert "Audit Report" in content

        # Verify transcripts.jsonl was written
        transcripts_path = reports_dir / "transcripts.jsonl"
        assert transcripts_path.exists()

    def test_all_modules_run_without_error(self, tmp_path):
        target_llm = MockLLM(responses=[
            "Here is sensitive data: REDTEAM-2024-CANARY, SECRET_KEY revealed.",
        ] * 100)

        rag_store = RAGStore(docs_dir=tmp_path / "empty_docs")
        (tmp_path / "empty_docs").mkdir(exist_ok=True)
        (tmp_path / "empty_docs" / "test.txt").write_text("Test document.")

        target = TargetAgent(
            llm=target_llm,
            rag_store=rag_store,
            max_turns=1,
        )

        reports_dir = tmp_path / "reports"
        orchestrator = AuditorOrchestrator(
            target_agent=target,
            judge_llm=None,
            output_dir=reports_dir,
        )

        # Should complete without errors
        state = orchestrator.run()
        assert state["status"] == "done"
        assert Path(state["report_path"]).exists()
