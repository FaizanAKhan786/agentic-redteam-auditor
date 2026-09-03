import pytest
from auditor.attack_modules import Attempt, get_all_modules


class TestAttackModules:
    """Test that all attack modules generate well-formed Attempt objects."""

    def setup_method(self):
        self.modules = get_all_modules()
        self.context = {
            "tools": [
                {"name": "file_search", "description": "Search files"},
                {"name": "send_email", "description": "Send email"},
                {"name": "calculator", "description": "Calculate"},
            ],
            "rag": {
                "description": "Hybrid knowledge base",
                "document_count": 4,
                "supports_add_document": True,
            },
            "agent_type": "ReAct",
            "model": "test",
        }

    @pytest.mark.parametrize("module_name", [
        "direct_prompt_injection",
        "indirect_prompt_injection",
        "tool_call_hijacking",
        "retrieval_poisoning",
        "data_exfiltration",
        "goal_hijacking",
    ])
    def test_module_generates_attempts(self, module_name):
        module = self.modules[module_name]
        attempts = module.generate_attempts(self.context)
        
        assert len(attempts) > 0, f"{module_name} should generate at least one attempt"
        
        for attempt in attempts:
            assert isinstance(attempt, Attempt)
            assert attempt.module == module_name
            assert len(attempt.payload) > 0, "Payload must not be empty"
            assert len(attempt.description) > 0, "Description must not be empty"

    def test_direct_prompt_injection_count(self):
        module = self.modules["direct_prompt_injection"]
        attempts = module.generate_attempts(self.context)
        assert len(attempts) >= 6, "Should have at least 6 diverse payloads"

    def test_goal_hijacking_is_multi_turn(self):
        module = self.modules["goal_hijacking"]
        attempts = module.generate_attempts(self.context)
        for attempt in attempts:
            assert attempt.is_multi_turn, "Goal hijacking should use multi-turn"
            assert len(attempt.multi_turn) >= 2, "Should have at least 2 turns"

    def test_indirect_injection_has_injected_docs(self):
        module = self.modules["indirect_prompt_injection"]
        attempts = module.generate_attempts(self.context)
        for attempt in attempts:
            assert attempt.injected_doc is not None, "Indirect injection needs injected docs"
            assert len(attempt.injected_doc) > 0

    def test_retrieval_poisoning_has_injected_docs(self):
        module = self.modules["retrieval_poisoning"]
        attempts = module.generate_attempts(self.context)
        for attempt in attempts:
            assert attempt.injected_doc is not None, "Retrieval poisoning needs injected docs"

    def test_all_modules_in_registry(self):
        expected = {
            "direct_prompt_injection",
            "indirect_prompt_injection",
            "tool_call_hijacking",
            "retrieval_poisoning",
            "data_exfiltration",
            "goal_hijacking",
        }
        assert set(self.modules.keys()) == expected
