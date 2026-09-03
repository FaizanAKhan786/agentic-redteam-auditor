"""LLM client abstraction — provider-agnostic, configured via .env.

Supports any OpenAI-compatible endpoint (Ollama, vLLM, LM Studio, OpenAI, etc.).
The judge can optionally use a separate endpoint to reduce self-grading bias.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, AIMessage, HumanMessage, SystemMessage

load_dotenv()


@dataclass
class LLMConfig:
    """Configuration for an LLM endpoint."""
    base_url: str
    api_key: str
    model: str
    temperature: float = 0.0


def _get_config(role: str) -> LLMConfig:
    """Resolve config for a given role from environment variables.
    
    Roles: 'target', 'auditor', 'judge'
    The judge falls back to the main config if JUDGE_API_BASE is not set.
    """
    base_url = os.getenv("OPENAI_API_BASE", "http://localhost:11434/v1")
    api_key = os.getenv("OPENAI_API_KEY", "not-needed-for-local")
    
    model_map = {
        "target": os.getenv("TARGET_MODEL", "llama3.1:8b"),
        "auditor": os.getenv("AUDITOR_MODEL", "llama3.1:8b"),
        "judge": os.getenv("JUDGE_MODEL", "llama3.1:8b"),
    }
    
    # Judge can use a separate endpoint
    if role == "judge":
        judge_base = os.getenv("JUDGE_API_BASE")
        judge_key = os.getenv("JUDGE_API_KEY")
        if judge_base:
            base_url = judge_base
            api_key = judge_key or api_key
    
    return LLMConfig(
        base_url=base_url,
        api_key=api_key,
        model=model_map.get(role, model_map["auditor"]),
    )


def get_llm(role: str = "auditor", temperature: float = 0.0) -> ChatOpenAI:
    """Get a ChatOpenAI instance configured for the given role.
    
    Args:
        role: One of 'target', 'auditor', 'judge'.
        temperature: Sampling temperature (0.0 = deterministic).
    
    Returns:
        A ChatOpenAI instance connected to the configured endpoint.
    """
    cfg = _get_config(role)
    return ChatOpenAI(
        base_url=cfg.base_url,
        api_key=cfg.api_key,
        model=cfg.model,
        temperature=temperature,
    )


class MockLLM:
    """A mock LLM for testing that returns canned responses.
    
    Usage:
        mock = MockLLM(responses=["response1", "response2"])
        result = mock.invoke([HumanMessage(content="hi")])
        # result.content == "response1"
        result = mock.invoke([HumanMessage(content="hello")])
        # result.content == "response2"
    """
    
    def __init__(self, responses: list[str] | None = None, default: str = "I am a mock LLM."):
        self.responses = list(responses) if responses else []
        self.default = default
        self._call_count = 0
        self.call_history: list[list[BaseMessage]] = []
    
    def invoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
        """Return the next canned response as an AIMessage."""
        self.call_history.append(messages)
        if self._call_count < len(self.responses):
            content = self.responses[self._call_count]
        else:
            content = self.default
        self._call_count += 1
        return AIMessage(content=content)
    
    async def ainvoke(self, messages: list[BaseMessage], **kwargs: Any) -> AIMessage:
        """Async version of invoke."""
        return self.invoke(messages, **kwargs)
    
    def bind_tools(self, tools: list, **kwargs: Any) -> 'MockLLM':
        """No-op for compatibility with LangChain tool binding."""
        return self
