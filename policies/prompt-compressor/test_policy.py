from __future__ import annotations

import importlib
import json
import sys
import types
import unittest
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import SimpleNamespace


class HeaderProcessingMode(Enum):
    SKIP = "SKIP"
    PROCESS = "PROCESS"


class BodyProcessingMode(Enum):
    SKIP = "SKIP"
    BUFFER = "BUFFER"
    STREAM = "STREAM"


@dataclass
class ProcessingMode:
    request_header_mode: HeaderProcessingMode = HeaderProcessingMode.SKIP
    request_body_mode: BodyProcessingMode = BodyProcessingMode.SKIP
    response_header_mode: HeaderProcessingMode = HeaderProcessingMode.SKIP
    response_body_mode: BodyProcessingMode = BodyProcessingMode.SKIP


class RequestPolicy:
    pass


@dataclass
class UpstreamRequestModifications:
    body: bytes | None = None
    dynamic_metadata: dict[str, dict[str, object]] = field(default_factory=dict)


@dataclass
class CompressorConfig:
    target_ratio: float
    min_input_tokens: int = 1
    min_input_bytes: int = 1


class CompressionError(Exception):
    pass


class InputTooShortError(CompressionError):
    pass


class NegativeGainError(CompressionError):
    pass


class FakeCompressor:
    instances: list["FakeCompressor"] = []

    def __init__(self, config: CompressorConfig):
        self.config = config
        self.calls: list[str] = []
        FakeCompressor.instances.append(self)

    def compress(self, text: str):
        self.calls.append(text)
        if text.startswith("raise-input-too-short"):
            raise InputTooShortError("input is too short")
        if text.startswith("raise-negative-gain"):
            raise NegativeGainError("compression would not help")
        if text.startswith("raise-compression-error"):
            raise CompressionError("compression failed")

        retained = max(1, int(len(text) * self.config.target_ratio))
        return SimpleNamespace(compressed=text[:retained])


def install_dependency_stubs() -> None:
    sdk_module = types.ModuleType("apip_sdk_core")
    sdk_module.BodyProcessingMode = BodyProcessingMode
    sdk_module.ProcessingMode = ProcessingMode
    sdk_module.RequestPolicy = RequestPolicy
    sdk_module.UpstreamRequestModifications = UpstreamRequestModifications
    sys.modules["apip_sdk_core"] = sdk_module

    compression_module = types.ModuleType("compression_prompt")
    compression_module.Compressor = FakeCompressor
    compression_module.CompressorConfig = CompressorConfig
    sys.modules["compression_prompt"] = compression_module

    compressor_submodule = types.ModuleType("compression_prompt.compressor")
    compressor_submodule.CompressionError = CompressionError
    compressor_submodule.InputTooShortError = InputTooShortError
    compressor_submodule.NegativeGainError = NegativeGainError
    sys.modules["compression_prompt.compressor"] = compressor_submodule


def load_policy_module():
    install_dependency_stubs()
    policy_dir = Path(__file__).resolve().parent
    if str(policy_dir) not in sys.path:
        sys.path.insert(0, str(policy_dir))
    sys.modules.pop("policy", None)
    return importlib.import_module("policy")


policy = load_policy_module()


def request_context(payload: object | bytes | str, present: bool = True):
    if isinstance(payload, bytes):
        body = payload
    elif isinstance(payload, str):
        body = payload.encode("utf-8")
    else:
        body = json.dumps(payload).encode("utf-8")
    return SimpleNamespace(body=SimpleNamespace(content=body, present=present))


class PromptCompressorPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        FakeCompressor.instances.clear()
        self._logger_disabled = policy.LOGGER.disabled
        policy.LOGGER.disabled = True

    def tearDown(self) -> None:
        policy.LOGGER.disabled = self._logger_disabled

    def test_mode_buffers_request_body_only(self) -> None:
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 0.5}]},
        )

        mode = instance.mode()

        self.assertEqual(HeaderProcessingMode.SKIP, mode.request_header_mode)
        self.assertEqual(BodyProcessingMode.BUFFER, mode.request_body_mode)
        self.assertEqual(HeaderProcessingMode.SKIP, mode.response_header_mode)
        self.assertEqual(BodyProcessingMode.SKIP, mode.response_body_mode)

    def test_normalize_params_applies_defaults_coerces_values_and_sorts_rules(self) -> None:
        params = policy.normalize_params(
            {
                "jsonPath": " $.messages[-1].content ",
                "rules": [
                    {"upperTokenLimit": -1, "type": "ratio", "value": "0.4"},
                    {"upperTokenLimit": "30.0", "type": "token", "value": "12"},
                    {"upperTokenLimit": 10, "type": "ratio", "value": 0.75},
                    {"upperTokenLimit": 3.5, "type": "ratio", "value": 0.8},
                    {"upperTokenLimit": -2, "type": "ratio", "value": 0.8},
                    {"upperTokenLimit": 20, "type": "unknown", "value": 0.8},
                    {"upperTokenLimit": 40, "type": "ratio", "value": False},
                    "not-a-rule",
                ],
            }
        )

        self.assertEqual("$.messages[-1].content", params.json_path)
        self.assertEqual(
            [
                policy.CompressionRule(10, "ratio", 0.75),
                policy.CompressionRule(30, "token", 12.0),
                policy.CompressionRule(-1, "ratio", 0.4),
            ],
            list(params.rules),
        )

    def test_normalize_params_falls_back_for_invalid_jsonpath_and_rules(self) -> None:
        params = policy.normalize_params({"jsonPath": "  ", "rules": "bad"})

        self.assertEqual(policy.DEFAULT_JSON_PATH, params.json_path)
        self.assertEqual((), params.rules)

    def test_rule_selection_and_ratio_resolution(self) -> None:
        rules = (
            policy.CompressionRule(10, "ratio", 0.75),
            policy.CompressionRule(30, "token", 12.0),
            policy.CompressionRule(-1, "ratio", 0.4),
        )

        self.assertEqual(rules[0], policy.select_rule(rules, 10))
        self.assertEqual(rules[1], policy.select_rule(rules, 20))
        self.assertEqual(rules[2], policy.select_rule(rules, 31))
        self.assertEqual(0.6, policy.resolve_ratio(rules[1], 20))
        self.assertEqual(1.0, policy.resolve_ratio(policy.CompressionRule(-1, "ratio", 1.5), 20))
        self.assertIsNone(policy.resolve_ratio(policy.CompressionRule(-1, "token", 20), 20))

    def test_jsonpath_extracts_and_updates_nested_array_values(self) -> None:
        payload = {
            "messages": [
                {"content": "first"},
                {"content": "second"},
            ]
        }

        self.assertEqual(
            "second",
            policy.extract_string_value_from_jsonpath(payload, "$.messages[-1].content"),
        )

        policy.set_value_at_jsonpath(payload, "$.messages[-1].content", "updated")

        self.assertEqual("updated", payload["messages"][1]["content"])

    def test_jsonpath_rejects_missing_or_non_string_targets(self) -> None:
        payload = {"messages": [{"content": {"text": "not a string"}}]}

        with self.assertRaises(policy.JSONPathError):
            policy.extract_string_value_from_jsonpath(payload, "$.messages[0].content")

        with self.assertRaises(policy.JSONPathError):
            policy.extract_string_value_from_jsonpath(payload, "$.messages[1].content")

        with self.assertRaises(policy.JSONPathError):
            policy.set_value_at_jsonpath(payload, "$.messages[0].missing", "updated")

    def test_compresses_default_chat_prompt_and_sets_metadata(self) -> None:
        original_text = "abcdefgh" * 10
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 0.5}]},
        )

        action = instance.on_request_body(
            execution_ctx=None,
            ctx=request_context({"messages": [{"role": "user", "content": original_text}]}),
            params={},
        )

        self.assertIsInstance(action, UpstreamRequestModifications)
        updated_payload = json.loads(action.body)
        self.assertEqual(original_text[:40], updated_payload["messages"][0]["content"])

        metadata = action.dynamic_metadata[policy.DYNAMIC_METADATA_NAMESPACE]
        self.assertTrue(metadata["compression_applied"])
        self.assertFalse(metadata["selective_mode"])
        self.assertEqual(0, metadata["tagged_segments"])
        self.assertEqual(1, metadata["compressed_segments"])
        self.assertEqual(20, metadata["input_tokens_estimated"])
        self.assertEqual(10, metadata["output_tokens_estimated"])

        self.assertEqual(1, len(FakeCompressor.instances))
        self.assertEqual(0.5, FakeCompressor.instances[0].config.target_ratio)
        self.assertEqual([original_text], FakeCompressor.instances[0].calls)

    def test_compresses_configured_jsonpath_with_token_rule(self) -> None:
        original_text = "0123456789" * 8
        instance = policy.get_policy(
            metadata={},
            params={
                "jsonPath": "$.prompt.text",
                "rules": [{"upperTokenLimit": -1, "type": "token", "value": 5}],
            },
        )

        action = instance.on_request_body(
            execution_ctx=None,
            ctx=request_context({"prompt": {"text": original_text}}),
            params={},
        )

        updated_payload = json.loads(action.body)
        self.assertEqual(original_text[:20], updated_payload["prompt"]["text"])
        self.assertEqual(0.25, FakeCompressor.instances[0].config.target_ratio)

    def test_selective_tags_compress_only_tagged_regions_and_are_removed(self) -> None:
        tagged_region = "z" * 40
        original_text = f"keep this {policy.OPEN_TAG}{tagged_region}{policy.CLOSE_TAG} tail"
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 0.5}]},
        )

        action = instance.on_request_body(
            execution_ctx=None,
            ctx=request_context({"messages": [{"content": original_text}]}),
            params={},
        )

        updated_payload = json.loads(action.body)
        self.assertEqual("keep this " + ("z" * 20) + " tail", updated_payload["messages"][0]["content"])

        metadata = action.dynamic_metadata[policy.DYNAMIC_METADATA_NAMESPACE]
        self.assertTrue(metadata["compression_applied"])
        self.assertTrue(metadata["selective_mode"])
        self.assertEqual(1, metadata["tagged_segments"])
        self.assertEqual(1, metadata["compressed_segments"])
        self.assertEqual([tagged_region], FakeCompressor.instances[0].calls)

    def test_nested_selective_tags_are_treated_as_one_region(self) -> None:
        original_text = (
            "start "
            f"{policy.OPEN_TAG}abc{policy.OPEN_TAG}def{policy.CLOSE_TAG}ghi{policy.CLOSE_TAG}"
            " end"
        )
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 0.5}]},
        )

        transformed, summary = instance._transform_text(original_text)

        self.assertEqual("start abcd end", transformed)
        self.assertTrue(summary.selective_mode)
        self.assertEqual(1, summary.tagged_segments)
        self.assertEqual(1, summary.compressed_segments)
        self.assertEqual(["abcdefghi"], FakeCompressor.instances[0].calls)

    def test_returns_none_when_request_body_is_absent_invalid_or_not_json(self) -> None:
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 0.5}]},
        )

        self.assertIsNone(
            instance.on_request_body(None, SimpleNamespace(body=None), {})
        )
        self.assertIsNone(
            instance.on_request_body(None, request_context({"messages": [{"content": "abc"}]}, present=False), {})
        )
        self.assertIsNone(
            instance.on_request_body(None, request_context(b"{not json"), {})
        )

    def test_returns_none_when_jsonpath_is_missing_or_not_a_string(self) -> None:
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 0.5}]},
        )

        self.assertIsNone(
            instance.on_request_body(None, request_context({"messages": []}), {})
        )
        self.assertIsNone(
            instance.on_request_body(
                None,
                request_context({"messages": [{"content": {"nested": "value"}}]}),
                {},
            )
        )

    def test_returns_none_when_no_rule_reduces_the_prompt(self) -> None:
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 1.0}]},
        )

        action = instance.on_request_body(
            execution_ctx=None,
            ctx=request_context({"messages": [{"content": "abcdefgh" * 10}]}),
            params={},
        )

        self.assertIsNone(action)
        self.assertEqual([], FakeCompressor.instances)

    def test_returns_none_when_compressor_reports_non_fatal_failure(self) -> None:
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 0.5}]},
        )

        action = instance.on_request_body(
            execution_ctx=None,
            ctx=request_context({"messages": [{"content": "raise-input-too-short" + ("x" * 40)}]}),
            params={},
        )

        self.assertIsNone(action)

    def test_compressor_instances_are_cached_by_rounded_ratio(self) -> None:
        instance = policy.get_policy(
            metadata={},
            params={"rules": [{"upperTokenLimit": -1, "type": "ratio", "value": 0.5}]},
        )

        first = instance._get_compressor(0.3333331)
        second = instance._get_compressor(0.3333334)
        third = instance._get_compressor(0.333334)

        self.assertIs(first, second)
        self.assertIsNot(first, third)
        self.assertEqual(2, len(FakeCompressor.instances))


if __name__ == "__main__":
    unittest.main()
