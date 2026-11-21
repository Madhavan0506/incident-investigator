import json
import socket
import unittest
from unittest.mock import MagicMock, patch

from incident_agent.local_model import LocalModel, ModelError


class LocalModelTests(unittest.TestCase):
    def setUp(self):
        self.transport_patch = patch("incident_agent.local_model.http.client.HTTPConnection")
        self.transport = self.transport_patch.start()
        self.addCleanup(self.transport_patch.stop)
        self.connection = self.transport.return_value

    def _response(self, payload, status=200):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = status
        response.read.return_value = json.dumps(payload).encode("utf-8")
        return response

    def test_native_chat_and_token_counts(self):
        tool_call = {
            "id": "call-1",
            "function": {"index": 0, "name": "search_logs", "arguments": {"query": "db_timeout"}},
        }
        assistant_call = {"role": "assistant", "content": "", "tool_calls": [tool_call]}
        final_message = {"role": "assistant", "content": '{"diagnosis": null}'}
        self.connection.getresponse.side_effect = [
            self._response({"capabilities": ["completion", "tools"]}),
            self._response({
                "done": True,
                "message": assistant_call,
                "prompt_eval_count": 12,
                "eval_count": 5,
            }),
            self._response({
                "done": True,
                "message": final_message,
                "prompt_eval_count": 22,
                "eval_count": 6,
            }),
        ]
        model = LocalModel("qwen3:4b", timeout=30.0)
        messages = [{"role": "user", "content": "Investigate db_timeout"}]
        tools = [{"type": "function", "function": {"name": "search_logs"}}]

        self.assertEqual(model.complete(messages, tools), assistant_call)
        messages.append(assistant_call)
        messages.append({"role": "tool", "tool_name": "search_logs", "content": "evidence"})
        self.assertEqual(model.complete(messages, tools), final_message)
        self.assertEqual((model.input_tokens, model.output_tokens), (34, 11))
        self.transport.assert_called_with("127.0.0.1", 11434, timeout=30.0)

        preflight, first_chat, second_chat = self.connection.request.call_args_list
        self.assertEqual(preflight.args, ("POST", "/api/show"))
        self.assertEqual(json.loads(preflight.kwargs["body"]), {"model": "qwen3:4b:local"})
        self.assertEqual(first_chat.args, ("POST", "/api/chat"))
        payload = json.loads(second_chat.kwargs["body"])
        self.assertEqual(payload["model"], "qwen3:4b:local")
        self.assertFalse(payload["stream"])
        self.assertFalse(payload["think"])
        self.assertEqual(payload["messages"], messages)
        self.assertEqual(payload["tools"], tools)

    def test_no_chat_on_cloud_alias_preflight(self):
        self.connection.getresponse.return_value = self._response({
            "capabilities": ["completion", "tools"],
            "remote_host": "https://ollama.com",
        })
        with self.assertRaisesRegex(ModelError, "remote model"):
            LocalModel("internal-alias").complete([{"role": "user", "content": "evidence"}], [])
        self.assertEqual(self.connection.request.call_count, 1)
        self.assertEqual(self.connection.request.call_args.args, ("POST", "/api/show"))

    def test_cloud_model_names_rejected_before_connection(self):
        for model_name in ("qwen3:cloud", "qwen3:4b-cloud", "qwen3:4b:cloud", "https://ollama.com/x"):
            with self.subTest(model_name=model_name), self.assertRaises(ModelError):
                LocalModel(model_name)
        self.transport.assert_not_called()

    def test_redirect_rejected_and_connection_closed(self):
        self.connection.getresponse.return_value = self._response({}, status=302)
        with self.assertRaisesRegex(ModelError, "HTTP 302"):
            LocalModel("qwen3").complete([], [])
        self.assertEqual(self.connection.request.call_count, 1)
        self.connection.close.assert_called_once()

    def test_timeout_reports_local_server_error_and_closes_connection(self):
        self.connection.getresponse.side_effect = socket.timeout()
        with self.assertRaisesRegex(ModelError, "timed out"):
            LocalModel("qwen3").complete([], [])
        self.connection.close.assert_called_once()

    def test_malformed_model_tool_arguments_fail_closed(self):
        self.connection.getresponse.side_effect = [
            self._response({"capabilities": ["tools"]}),
            self._response({
                "done": True,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{"function": {"name": "search_logs", "arguments": "not an object"}}],
                },
            }),
        ]
        with self.assertRaisesRegex(ModelError, "malformed tool call"):
            LocalModel("qwen3").complete([], [])


if __name__ == "__main__":
    unittest.main()
