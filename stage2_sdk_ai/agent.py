from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class AgentMemory:
    messages: list[dict] = field(default_factory=list)

    def add(self, role: str, content: str) -> None:
        self.messages.append({"role": role, "content": content})

    def history(self, limit: int = 10) -> list[dict]:
        return self.messages[-limit:]

    def clear(self) -> None:
        self.messages.clear()

TOOL_PATTERN = re.compile(r"TOOL:\s*(\w+)\s*:\s*(.*)", re.IGNORECASE)

class Agent:
    def __init__(self, client, max_steps: int = 5):
        self.client = client
        self.max_steps = max_steps
        self.memory = AgentMemory()
        self._tools: dict[str, Callable] = {}

    def register_tool(self, name: str, func: Callable) -> None:
        self._tools[name] = func
        self.client.register_tool(name, func)

    async def run(self, prompt: str) -> str:
        self.memory.add("user", prompt)
        current = prompt

        for _ in range(self.max_steps):
            # RAG context without polluting tool name detection
            rag_ctx = ""
            if hasattr(self.client, "similarity_search") and self.client._store:
                try:
                    ctx = await self.client.similarity_search(prompt, k=2)
                    if ctx:
                        rag_ctx = " | ".join(ctx)
                except Exception:
                    rag_ctx = ""

            # 1. LLM step uses plain complete (not complete_with_tools)
            if rag_ctx:
                llm_prompt = f"Context: {rag_ctx}\nQuestion: {current}"
            else:
                llm_prompt = current

            out = await self.client.complete(llm_prompt)
            # Also allow explicit tool call syntax: if LLM returns TOOL:name:arg
            self.memory.add("assistant", out)

            # 2. Check if user prompt itself asks for a tool -> multi-step
            tool_to_call = None
            tool_arg = current

            # direct request in original prompt
            low = prompt.lower()
            for name in self._tools:
                if name in low:
                    tool_to_call = name
                    break

            # or LLM output says TOOL:xxx
            m = TOOL_PATTERN.search(out)
            if m:
                tool_to_call = m.group(1).lower()
                tool_arg = m.group(2).strip()

            if tool_to_call and tool_to_call in self._tools:
                try:
                    res = self._tools[tool_to_call](tool_arg)
                    obs = f"OBSERVATION:{tool_to_call}:{res}"
                    self.memory.add("tool", obs)
                    # next iteration uses observation as context, but final will include tool result
                    current = f"{prompt} -> {obs}"
                    if "calc" in tool_to_call or "search" in tool_to_call:
                        return f"tool:{tool_to_call}:{res} with context {rag_ctx}"
                    continue
                except Exception as e:
                    self.memory.add("tool", f"ERROR:{e}")
                    break

            return out if not rag_ctx else f"{out} | ctx:{rag_ctx}"

        hist = "\n".join(
            [f"{m['role']}:{m['content'][:80]}" for m in self.memory.history()]
        )
        return f"Final after {self.max_steps} steps. History: {hist} | last:{out}"
