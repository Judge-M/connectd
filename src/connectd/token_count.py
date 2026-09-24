"""Registry-bound local token accounting for metered model requests."""

import hashlib
import json
from pathlib import Path


class TokenizerError(ValueError):
    pass


def _nonnegative_int(value, label: str) -> int:
    if type(value) is not int or value < 0:
        raise TokenizerError(f"{label} must be a nonnegative integer")
    return value


def _load(config: dict):
    kind = config.get("kind")
    if kind == "tiktoken":
        if set(config) != {"kind", "encoding_name", "overhead_per_message",
                           "overhead_per_tool", "safety_margin_tokens"}:
            raise TokenizerError("tiktoken configuration needs encoding_name and all overhead fields")
        try:
            import tiktoken
            encoding = tiktoken.get_encoding(config["encoding_name"])
        except (ImportError, KeyError, ValueError, TypeError) as exc:
            raise TokenizerError("registered tiktoken encoding is unavailable") from exc
        return lambda value: len(encoding.encode(value, disallowed_special=()))
    if kind == "huggingface_json":
        if set(config) != {"kind", "path", "sha256", "overhead_per_message",
                           "overhead_per_tool", "safety_margin_tokens"}:
            raise TokenizerError("Hugging Face configuration needs a pinned local tokenizer file")
        try:
            path = Path(config["path"])
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != config["sha256"]:
                raise TokenizerError("registered tokenizer file hash changed")
            from tokenizers import Tokenizer
            tokenizer = Tokenizer.from_file(str(path))
        except (OSError, ImportError, ValueError, TypeError) as exc:
            raise TokenizerError("registered local tokenizer is unavailable") from exc
        return lambda value: len(tokenizer.encode(value, add_special_tokens=False).ids)
    raise TokenizerError("tokenizer kind must be tiktoken or huggingface_json")


def validate_tokenizer(config: dict) -> None:
    if not isinstance(config, dict):
        raise TokenizerError("paid node needs a tokenizer configuration")
    for key in ("overhead_per_message", "overhead_per_tool", "safety_margin_tokens"):
        _nonnegative_int(config.get(key), key)
    _load(config)("registration check")


def count_prompt_tokens(payload: dict, config: dict | str) -> int:
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except ValueError as exc:
            raise TokenizerError("registered tokenizer configuration is invalid") from exc
    validate_tokenizer(config)
    messages = payload.get("messages")
    tools = payload.get("tools", [])
    if not isinstance(messages, list) or not messages or not isinstance(tools, list):
        raise TokenizerError("paid inference requires messages and a tool list")
    if not all(isinstance(message, dict) for message in messages):
        raise TokenizerError("paid inference messages must be objects")
    count = _load(config)
    encoded = json.dumps({"messages": messages, "tools": tools,
                          "tool_choice": payload.get("tool_choice")},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return (count(encoded) + len(messages) * config["overhead_per_message"] +
            len(tools) * config["overhead_per_tool"] + config["safety_margin_tokens"])
