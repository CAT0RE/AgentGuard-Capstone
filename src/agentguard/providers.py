from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Protocol


@dataclass(frozen=True)
class FunctionCall:
    call_id: str
    name: str
    arguments: Dict[str, object]


@dataclass
class ModelTurn:
    """Provider-neutral representation of one model response."""

    items: List[dict]
    text: str = ""

    @property
    def function_calls(self) -> List[FunctionCall]:
        calls: List[FunctionCall] = []
        for item in self.items:
            if item.get("type") != "function_call":
                continue
            raw_arguments = item.get("arguments", "{}")
            arguments = json.loads(raw_arguments) if isinstance(raw_arguments, str) else dict(raw_arguments)
            if not isinstance(arguments, dict):
                raise ValueError(f"Function arguments for {item.get('name')} must be a JSON object")
            calls.append(
                FunctionCall(
                    call_id=str(item.get("call_id") or item.get("id") or ""),
                    name=str(item.get("name") or ""),
                    arguments=arguments,
                )
            )
        return calls


class AgentProvider(Protocol):
    def respond(self, *, input_items: List[dict], tools: List[dict], instructions: str) -> ModelTurn:
        ...


Transport = Callable[[str, Dict[str, str], bytes, float], dict]


class OpenAIResponsesProvider:
    """Minimal dependency-free adapter for the OpenAI Responses API.

    The adapter intentionally exposes only application-defined function tools.
    The monitored runner remains responsible for executing or blocking them.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 60.0,
        transport: Optional[Transport] = None,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.transport = transport or self._post_json
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is required when provider=openai")

    def respond(self, *, input_items: List[dict], tools: List[dict], instructions: str) -> ModelTurn:
        payload = {
            "model": self.model,
            "instructions": instructions,
            "input": input_items,
            "tools": tools,
            "parallel_tool_calls": False,
            "store": False,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        response = self.transport(
            f"{self.base_url}/responses",
            headers,
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            self.timeout,
        )
        items = list(response.get("output") or [])
        return ModelTurn(items=items, text=self._output_text(response, items))

    @staticmethod
    def _output_text(response: dict, items: List[dict]) -> str:
        if response.get("output_text"):
            return str(response["output_text"])
        parts: List[str] = []
        for item in items:
            if item.get("type") != "message":
                continue
            for content in item.get("content") or []:
                if content.get("type") == "output_text" and content.get("text"):
                    parts.append(str(content["text"]))
        return "\n".join(parts)

    @staticmethod
    def _post_json(url: str, headers: Dict[str, str], body: bytes, timeout: float) -> dict:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise RuntimeError(f"OpenAI API request failed ({exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenAI API connection failed: {exc.reason}") from exc


class ReplayProvider:
    """Deterministic provider used for offline experiments and tests."""

    def __init__(self, turns: List[ModelTurn]) -> None:
        self.turns = list(turns)
        self.index = 0
        self.requests: List[dict] = []

    def respond(self, *, input_items: List[dict], tools: List[dict], instructions: str) -> ModelTurn:
        self.requests.append({"input": list(input_items), "tools": list(tools), "instructions": instructions})
        if self.index >= len(self.turns):
            return message_turn("No further action is required.")
        turn = self.turns[self.index]
        self.index += 1
        return turn


def function_turn(call_id: str, name: str, arguments: dict) -> ModelTurn:
    return ModelTurn(
        items=[
            {
                "type": "function_call",
                "call_id": call_id,
                "name": name,
                "arguments": json.dumps(arguments, ensure_ascii=False),
            }
        ]
    )


def message_turn(text: str) -> ModelTurn:
    return ModelTurn(
        items=[{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": text}]}],
        text=text,
    )

