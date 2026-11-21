"""Ollama's native chat API for an already-installed local model."""

import http.client
import json
import math
import re
import socket


_HOST = "127.0.0.1"
_PORT = 11434
_MAX_BODY_BYTES = 2 * 1024 * 1024
_MODEL_NAME = re.compile(
    r"[a-zA-Z0-9][a-zA-Z0-9_.-]*(?:/[a-zA-Z0-9][a-zA-Z0-9_.-]*)*"
    r"(?::[a-zA-Z0-9][a-zA-Z0-9_.-]*)?"
)


class ModelError(RuntimeError):
    """The local model could not return a usable response."""


class LocalModel:
    def __init__(self, model: str, *, timeout: float = 90.0):
        if (
            not isinstance(model, str)
            or len(model) > 160
            or not _MODEL_NAME.fullmatch(model)
            or model.lower().endswith((":cloud", "-cloud", ":local"))
        ):
            raise ModelError("Use an installed local Ollama model name, for example qwen3:4b-instruct.")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ModelError("The model timeout must be a positive finite number.")

        self.model = model
        self.input_tokens = 0
        self.output_tokens = 0
        tagged_model = model if ":" in model else f"{model}:latest"
        # Ollama's explicit source selector keeps a local alias from invoking a cloud model.
        self._local_ref = f"{tagged_model}:local"
        self._timeout = timeout
        self._checked = False

    def complete(self, messages: list[dict], tools: list[dict]) -> dict:
        if not self._checked:
            details = self._post("/api/show", {"model": self._local_ref})
            capabilities = details.get("capabilities")
            if not isinstance(capabilities, list) or "tools" not in capabilities:
                raise ModelError("The installed Ollama model must advertise native tool calling.")
            self._checked = True

        payload = self._post(
            "/api/chat",
            {
                "model": self._local_ref,
                "messages": messages,
                "tools": tools,
                "stream": False,
                "think": False,
                "options": {"temperature": 0, "num_predict": 1024},
            },
        )
        input_tokens = _usage(payload.get("prompt_eval_count"))
        output_tokens = _usage(payload.get("eval_count"))
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens

        if payload.get("done") is not True or payload.get("done_reason") == "length":
            raise ModelError("Ollama returned an incomplete chat response.")
        return _assistant_message(payload.get("message"))

    def _post(self, path: str, data: dict) -> dict:
        try:
            body = json.dumps(data, ensure_ascii=True, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise ModelError("The Ollama request is invalid JSON.") from exc
        if len(body) > _MAX_BODY_BYTES:
            raise ModelError("The Ollama request exceeds the 2 MiB limit.")

        connection = http.client.HTTPConnection(_HOST, _PORT, timeout=self._timeout)
        try:
            connection.request("POST", path, body=body, headers={"Content-Type": "application/json"})
            with connection.getresponse() as response:
                if response.status == 404:
                    raise ModelError("Ollama could not find the model. Use a current server and an installed local model.")
                if response.status != 200:
                    raise ModelError(f"Ollama rejected {path} with HTTP {response.status}.")
                raw = response.read(_MAX_BODY_BYTES + 1)
        except (TimeoutError, socket.timeout) as exc:
            raise ModelError("The local Ollama server timed out.") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise ModelError("Could not communicate with Ollama at 127.0.0.1:11434.") from exc
        finally:
            connection.close()

        if len(raw) > _MAX_BODY_BYTES:
            raise ModelError("The Ollama response exceeds the 2 MiB limit.")
        try:
            payload = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise ModelError("Ollama returned invalid JSON.") from exc
        if not isinstance(payload, dict) or "error" in payload:
            raise ModelError("Ollama returned an error or an invalid response.")
        if payload.get("remote_model") or payload.get("remote_host"):
            raise ModelError("Ollama reported a remote model. Local inference is required.")
        return payload


def _usage(value) -> int:
    # Ollama omits token counts when they are zero.
    if value is None:
        return 0
    if type(value) is not int or value < 0:
        raise ModelError("Ollama returned an invalid token count.")
    return value


def _assistant_message(message) -> dict:
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise ModelError("Ollama returned an invalid assistant message.")
    content = message.get("content", "")
    calls = message.get("tool_calls", [])
    if not isinstance(content, str) or not isinstance(calls, list) or not (content.strip() or calls):
        raise ModelError("Ollama returned an invalid assistant message.")

    result = {"role": "assistant", "content": content}
    if "thinking" in message:
        if not isinstance(message["thinking"], str):
            raise ModelError("Ollama returned an invalid thinking field.")
        result["thinking"] = message["thinking"]
    if calls:
        result["tool_calls"] = [_tool_call(call) for call in calls]
    return result


def _tool_call(call) -> dict:
    function = call.get("function") if isinstance(call, dict) else None
    if not isinstance(function, dict):
        raise ModelError("Ollama returned a malformed tool call.")
    name = function.get("name")
    arguments = function.get("arguments")
    if not isinstance(name, str) or not name.strip() or not isinstance(arguments, dict):
        raise ModelError("Ollama returned a malformed tool call.")
    result = {"function": {"name": name, "arguments": arguments}}
    if type(function.get("index")) is int:
        result["function"]["index"] = function["index"]
    if isinstance(call.get("id"), str):
        result["id"] = call["id"]
    return result
