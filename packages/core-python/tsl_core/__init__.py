import hashlib
import json
from typing import Any
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


def canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) > 2**53 - 1:
            raise ValueError("TSL canonicalization only allows safe integers in signed core objects")
        return str(value)
    if isinstance(value, float):
        raise ValueError("TSL canonicalization only allows safe integers in signed core objects")
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(str(key), ensure_ascii=False) + ":" + canonicalize(value[key]) for key in sorted(value)) + "}"
    raise TypeError(f"Unsupported value in TSL canonicalization: {type(value).__name__}")


def hash_domain(tag: str, payload: bytes) -> str:
    return "0x" + hashlib.sha256(tag.encode("utf-8") + b"\x00" + payload).hexdigest()


def sha256_hex(payload: bytes) -> str:
    return "0x" + hashlib.sha256(payload).hexdigest()


DETERMINISTIC_EVENT_HASH = "0xcf5cb36e4596ed4c446f2d24504407369a1fc4862928e86c340ec5270fcc3267"
DETERMINISTIC_COMMITMENT_HASH = "0xcc680d3c19dbbb9785640355a4756a498fb887c643dc04ef304689955381251d"
DETERMINISTIC_LEGACY_COMMITMENT_HASH = "0x174c377613f1fa94acc95d32408095c27330f5dfa088ee40cdcb81a503b25bb5"


def _hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value[2:] if value.startswith("0x") else value)


def _uint64be(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def commitment_hash(event_hash: str, signature: str) -> str:
    return hash_domain("tsl.commitment.v1", _hex_to_bytes(event_hash) + _hex_to_bytes(signature))


def legacy_commitment_hash(event_hash: str, signature: str) -> str:
    return sha256_hex(_hex_to_bytes(event_hash) + _hex_to_bytes(signature))


def merkle_leaf(index: int, commitment: str) -> str:
    return hash_domain("tsl.merkle.leaf.v1", _uint64be(index) + _hex_to_bytes(commitment))


def merkle_node(left: str, right: str) -> str:
    return hash_domain("tsl.merkle.node.v1", _hex_to_bytes(left) + _hex_to_bytes(right))


def merkle_root(commitments: list[str]) -> str:
    if not commitments:
        return "0x" + "00" * 32
    level = [merkle_leaf(index, commitment) for index, commitment in enumerate(commitments)]
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            if index + 1 < len(level):
                next_level.append(merkle_node(level[index], level[index + 1]))
            else:
                next_level.append(level[index])
        level = next_level
    return level[0]


def verify_ed25519(public_key_hex: str, message_hex: str, signature_hex: str) -> bool:
    try:
        key = VerifyKey(_hex_to_bytes(public_key_hex))
        key.verify(_hex_to_bytes(message_hex), _hex_to_bytes(signature_hex))
        return True
    except (BadSignatureError, ValueError):
        return False
