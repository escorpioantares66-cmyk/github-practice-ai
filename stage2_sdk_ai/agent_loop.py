from __future__ import annotations

import json
import os
from typing import Any

from .tools import TOOL_REGISTRY, _is_mock


def _mock_llm_pick_tool(query: str, step: int) -> dict[str, Any]:
    if step == 0:
        return {"tool": "search", "args": {"query": query, "top_k": 2}}
    if step == 1:
        return {"tool": "read_note", "args": {"path": "termux.md"}}
    return {"tool": "final", "args": {"answer": f"[MOCK FINAL] answer for {query}"}}

def _real_llm_pick_tool(query: str, history: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        from openai import OpenAI  # type: ignore

        key = os.getenv("OPENAI_API_KEY", "")
        client = OpenAI(api_key=key)
        prompt = (
            "You are an agent. Tools: search(query, top_k), "
            "read_note(path). Pick one as JSON "
            '{"tool": "...", "args": {...}} or final '
            '{"tool": "final", "args": {"answer": "..."}}.\n'
            f"Query: {query}\nHistory: {json.dumps(history)[:1500]}"
        )
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
        )
        text = resp.choices[0].message.content or ""
        return json.loads(text[text.find("{") : text.rfind("}") + 1])
    except Exception:
        return _mock_llm_pick_tool(query, len(history))

def run_agent(query: str, max_steps: int = 3) -> dict[str, Any]:
    history: list[dict[str, Any]] = []
    for step in range(max_steps):
        if _is_mock():
            pick = _mock_llm_pick_tool(query, step)
        else:
            pick = _real_llm_pick_tool(query, history)

        tool_name = pick.get("tool", "final")
        args = pick.get("args", {})

        if tool_name == "final":
            return {
                "query": query,
                "answer": args.get("answer", ""),
                "steps": history,
                "is_mock": _is_mock(),
            }

        tool_fn = TOOL_REGISTRY.get(tool_name)
        if tool_fn is None:
            history.append({"step": step, "error": f"unknown tool {tool_name}"})
            continue

        result = tool_fn(**args)
        history.append({"step": step, "tool": tool_name, "args": args, "result": result})

    return {
        "query": query,
        "answer": f"Stopped after {max_steps} steps",
        "steps": history,
        "is_mock": _is_mock(),
    }
