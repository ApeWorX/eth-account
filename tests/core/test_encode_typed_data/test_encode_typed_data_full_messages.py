import pytest
from copy import (
    deepcopy,
)
import json

from eth_utils import (
    ValidationError,
)
from hexbytes import (
    HexBytes,
)

from eth_account.messages import (
    _hash_eip191_message,
    encode_typed_data,
)
from tests.eip712_messages import (
    ALL_VALID_EIP712_MESSAGES,
    INVALID,
    ONE_ARG_INVALID,
    convert_to_3_arg,
)

all_valid = deepcopy(ALL_VALID_EIP712_MESSAGES)
invalid = deepcopy(INVALID)
one_arg_invalid = deepcopy(ONE_ARG_INVALID)


@pytest.mark.parametrize("test_cases", (all_valid, invalid, one_arg_invalid))
def test_there_are_no_duplicate_test_cases(test_cases):
    string_test_cases = [json.dumps(msg, sort_keys=True) for msg in test_cases.values()]
    assert len(string_test_cases) == len(set(string_test_cases))


@pytest.mark.parametrize("message", all_valid)
def test_valid_messages(message):
    assert encode_typed_data(full_message=all_valid[message]) == encode_typed_data(
        *convert_to_3_arg(all_valid[message])
    )


@pytest.mark.parametrize("message", invalid)
def test_invalid_messages(message):
    with pytest.raises(ValueError):
        encode_typed_data(full_message=invalid[message])

    with pytest.raises(ValueError):
        encode_typed_data(*convert_to_3_arg(invalid[message]))


@pytest.mark.parametrize("message", one_arg_invalid)
def test_messages_that_are_only_invalid_for_one_arg_encoding(message):
    with pytest.raises(ValidationError):
        encode_typed_data(full_message=one_arg_invalid[message])
    encode_typed_data(*convert_to_3_arg(one_arg_invalid[message]))


def _full_message_with_domain_types(domain_types):
    return {
        "types": {
            "EIP712Domain": domain_types,
            "Msg": [{"name": "x", "type": "uint256"}],
        },
        "primaryType": "Msg",
        "domain": {"name": "App", "chainId": 1},
        "message": {"x": 7},
    }


@pytest.mark.parametrize(
    "domain_types,expected_hash",
    (
        (
            # canonical order and types, same as the 3-arg encoding
            [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "0x7097837cbbc03cfaa632de20ba5e4e2e932cbf62a7a0caf6a170ca9c2575e285",
        ),
        (
            # fields in a different order
            [
                {"name": "chainId", "type": "uint256"},
                {"name": "name", "type": "string"},
            ],
            "0xfbb58b78111cf2239031139f02c28ee428f92fa6ad5e321bb5bf8110397dcb13",
        ),
        (
            # a field with a different type
            [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint64"},
            ],
            "0x02e2ac9098a4aeb53903a4652f2d5a928be888a73eb9c5ebaaa3583ebae32125",
        ),
    ),
    ids=["canonical", "reordered", "retyped"],
)
def test_full_message_domain_hashed_with_provided_eip712domain_types(
    domain_types, expected_hash
):
    # Expected hashes are from @metamask/eth-sig-util (V4) and viem's hashTypedData
    full_message = _full_message_with_domain_types(domain_types)
    signable = encode_typed_data(full_message=full_message)
    assert _hash_eip191_message(signable) == HexBytes(expected_hash)
