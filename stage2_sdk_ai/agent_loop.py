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


def _real_llm_pick_tool(
    query: str,
    history: list[dict[str, Any]],
) -> dict[str, Any]:
    key = os.getenv("OPENAI_API_KEY", "").strip()

    if not key:
        print("OPENAI_API_KEY is missing; using mock fallback.")
        return _mock_llm_pick_tool(query, len(history))

    try:
        from openai import OpenAI

        client = OpenAI(api_key=key)
        prompt = (
            "You are an agent. Tools: search(query, top_k), "
            "read_note(path). Pick one as JSON "
            '{"tool": "...", "args": {...}} or final '
            '{"tool": "final", "args": {"answer": "..."}}.\n'
            f"Query: {query}\nHistory: {json.dumps(history)[:1500]}"
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
        )

        text = response.choices[0].message.content or ""
        start = text.find("{")
        end = text.rfind("}")

        if start < 0 or end < start:
            raise ValueError("Model returned no valid JSON object.")

        result = json.loads(text[start : end + 1])

        if not isinstance(result, dict) or not isinstance(
            result.get("args", {}), dict
        ):
            raise ValueError("Model returned an invalid tool selection.")

        return result

    except ImportError:
        print("OpenAI package unavailable; using mock fallback.")
    except Exception as exc:
        print(
            f"OpenAI request failed: {type(exc).__name__}: {exc}; "
            "using mock fallback."
        )

    return _mock_llm_pick_tool(query, len(history))


def run_agent(query: str, max_steps: int = 3, top_k: int = 3) -> dict[str, Any]:
    history: list[dict[str, Any]] = []
    for step in range(max_steps):
        if _is_mock():
            pick = _mock_llm_pick_tool(query, step)
        else:
            pick = _real_llm_pick_tool(query, history)

        tool_name: str = pick.get("tool", "final")
        args = pick.get("args", {})

        if tool_name == "final":
            return {
                "query": query,
                "answer": args.get("answer", ""),
                "steps": history,
                "sources": _collect_sources(history),
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
        "sources": _collect_sources(history),
        "is_mock": _is_mock(),
    }


def _collect_sources(history):
    sources = []
    for step in history:
        result = step.get("result") or {}
        if step.get("tool") == "search":
            for r in result.get("results", []):
                sources.append({"text": r.get("text", ""), "score": r.get("score")})
        elif step.get("tool") == "read_note":
            sources.append({"path": result.get("path", ""), "text": result.get("content", "")})
    return sources
