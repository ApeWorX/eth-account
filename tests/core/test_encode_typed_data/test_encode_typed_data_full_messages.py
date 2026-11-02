import pytest
from copy import (
    deepcopy,
)
import json

from eth_utils import (
    ValidationError,
)

from eth_account.messages import (
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


@pytest.mark.parametrize(
    "value, expected",
    [
        ([], False),
        ([0], True),
        ({}, False),
        ({"enabled": 0}, True),
        (set(), False),
        ({0}, True),
        (bytearray(), False),
        (bytearray(b"\x00"), True),
    ],
)
def test_encode_typed_data_bool_with_unhashable_value(value, expected):
    message_types = {"Message": [{"name": "enabled", "type": "bool"}]}
    assert encode_typed_data(
        {}, message_types, {"enabled": value}
    ) == encode_typed_data({}, message_types, {"enabled": expected})
