from eth_abi import encode
from eth_utils import keccak

from eth_account._utils.encode_typed_data.encoding_and_hashing import (
    encode_type,
    hash_eip712_message,
    hash_struct,
    hash_type,
)


def test_type_hash_tracks_mutable_definition_and_dependency():
    types = {
        "Asset": [{"name": "amount", "type": "uint256"}],
        "Order": [{"name": "asset", "type": "Asset"}],
    }
    before = hash_type("Order", types)
    types["Asset"][0]["type"] = "int256"
    after = hash_type("Order", types)
    assert after == keccak(text=encode_type("Order", types))
    assert before != after
    types["Asset"][0]["type"] = "uint256"
    assert hash_type("Order", types) == before


def test_type_hash_remains_correct_after_many_distinct_types():
    for _ in range(2):
        for i in range(180):
            types = {"Asset": [{"name": f"amount{i}", "type": "uint256"}]}
            assert hash_type("Asset", types) == keccak(text=encode_type("Asset", types))


def test_type_definition_mutation_during_message_encoding():
    types = {
        "Asset": [{"name": "x", "type": "uint256"}],
        "Order": [
            {"name": "left", "type": "Asset"},
            {"name": "right", "type": "Asset"},
        ],
    }
    order_hash = hash_type("Order", types)
    left_hash = hash_struct("Asset", types, {"x": 1})
    types["Asset"][0]["type"] = "int256"
    right_hash = hash_struct("Asset", types, {"x": 2})
    types["Asset"][0]["type"] = "uint256"

    class MutatingData(dict):
        def get(self, key, default=None):
            if key == "right":
                types["Asset"][0]["type"] = "int256"
            return super().get(key, default)

    data = MutatingData(left={"x": 1}, right={"x": 2})
    assert hash_eip712_message(types, data) == keccak(
        encode(["bytes32"] * 3, [order_hash, left_hash, right_hash])
    )
