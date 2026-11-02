import pytest
import re

from eth_abi.exceptions import (
    EncodingTypeError,
    ValueOutOfBounds,
)

from eth_account._utils.encode_typed_data.encoding_and_hashing import (
    encode_data,
    encode_field,
    encode_type,
    find_type_dependencies,
    get_primary_type,
    hash_domain,
    hash_eip712_message,
    hash_struct,
    hash_type,
)


@pytest.mark.parametrize(
    "types, expected",
    (
        (
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
            },
            "Person",
        ),
        (
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            "Mail",
        ),
        (
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friend", "type": "Person"},
                ],
            },
            "Person",
        ),
        (
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friends", "type": "Person[]"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "attachments", "type": "Attachment[]"},
                ],
                "Attachment": [
                    {"name": "from", "type": "string"},
                ],
            },
            "Mail",
        ),
    ),
    ids=[
        "primary_type with no dependencies",
        "primary_type with one dependency",
        "primary_type with recursive dependency",
        "primary_type with array dependency",
    ],
)
def test_get_primary_type_pass(types, expected):
    assert get_primary_type(types) == expected


@pytest.mark.parametrize(
    "types, expected",
    (
        (
            {
                "Person": [
                    {"name": "other_person", "type": "OtherPerson"},
                ],
                "OtherPerson": [
                    {"name": "Person", "type": "Person"},
                ],
            },
            {
                "expected_exception": ValueError,
                "match": "Unable to determine primary type",
            },
        ),
        (
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
                "Mail": [
                    {"name": "type", "type": "string"},
                ],
            },
            {
                "expected_exception": ValueError,
                "match": "Unable to determine primary type",
            },
        ),
    ),
    ids=[
        "primary_type circular dependency",
        "two primary types that do not depend on each other",
    ],
)
def test_get_primary_type_fail(types, expected):
    with pytest.raises(**expected):
        get_primary_type(types)


@pytest.mark.parametrize(
    "name, type_, value, expected",
    (
        (
            "custom_type",
            "Sample",
            None,
            (
                "bytes32",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # noqa: E501
            ),
        ),
        (
            "name",
            "string",
            None,
            (
                "bytes32",
                b"",
            ),
        ),
        (
            "some_bytes",
            "bytes",
            None,
            (
                "bytes32",
                b"",
            ),
        ),
        (
            "some_bytes",
            "bytes",
            "27",
            (
                "bytes32",
                b"X\xa2\x80\xf7OW\xbf\x05\x1c@\xf0`\x13\x9d\xc7G\xe0\x15\xbeR\xf6\x8cW\xe2\xc4\xab.K\xd4\x14oC",  # noqa: E501
            ),
        ),
        (
            "some_bytes",
            "bytes",
            27,
            (
                "bytes32",
                b"$\xd6\xd74\x14_\x07\x1a\xa6\xa2v?\xdd\xcaX\x10\xbd\x12#l->X\x9d*z\xdf\\\xa6\x9c\xc9\xc6",  # noqa: E501
            ),
        ),
        (
            "some_bytes",
            "bytes8",
            -27,
            (
                "bytes8",
                b"\x00",
            ),
        ),
        (
            "some_bytes",
            "bytes",
            -27,
            (
                "bytes32",
                b"\xbc6x\x9ez\x1e(\x146FB)\x82\x8f\x81}f\x12\xf7\xb4w\xd6e\x91\xff\x96\xa9\xe0d\xbc\xc9\x8a",  # noqa: E501
            ),
        ),
        (
            "some_bytes",
            "bytes",
            "0xdeadbeef",
            (
                "bytes32",
                b"\xd4\xfdN\x18\x912'06D\x9f\xc9\xe1\x11\x98\xc79\x16\x1bL\x01\x16\xa9\xa2\xdc\xcd\xfa\x1cI \x06\xf1",  # noqa: E501
            ),
        ),
        (
            "some_bytes",
            "bytes",
            b"\xd4\xfdN\x18\x912'06D\x9f\xc9\xe1\x11",
            (
                "bytes32",
                b"p\xa6\xe6 \xc0:\xff\xea9\x0f\xad\x1a\xab\xf8\xf7\xdc\x1b\xd1\x82\x1c\xe4\xd5\xa1,m3+\x15X\x98M\xaf",  # noqa: E501
            ),
        ),
        (
            "name",
            "string",
            27,
            (
                "bytes32",
                b"$\xd6\xd74\x14_\x07\x1a\xa6\xa2v?\xdd\xcaX\x10\xbd\x12#l->X\x9d*z\xdf\\\xa6\x9c\xc9\xc6",  # noqa: E501
            ),
        ),
        (
            "name",
            "string",
            "Bob",
            (
                "bytes32",
                b"(\xca\xc3\x18\xa8l\x8a\nj\x91V\xc2\xdb\xa2\xc8\xc266w\xba\x05\x14\xefae\x92\xd8\x15W\xe6y\xb6",  # noqa: E501
            ),
        ),
        (
            "names",
            "string[]",
            ["Bob", "Jim"],
            (
                "bytes32",
                b"@u,V\x9a<\x1a0\x1d\xf0b\xda\xc4\x98\x10/\xfb\xcf\x06\xba\x96pDC/\n\xb5\xe9\x9dB\t!",  # noqa: E501
            ),
        ),
        (
            "names",
            "string[][]",
            [["Bob", "Jim"], ["Amy", "Sal"]],
            (
                "bytes32",
                b"\xcd\x13is\x93\xf4\xf8^\xa7\x9bi\xec\x8cE\xfc\xfe\xab\xcc9p\x0c\xa8\xecR$\xbc]\xc6[\x10-1",  # noqa: E501
            ),
        ),
        (
            "a_bool",
            "bool",
            False,
            (
                "bool",
                False,
            ),
        ),
        (
            "a_bool",
            "bool",
            True,
            (
                "bool",
                True,
            ),
        ),
        (
            "a_bool",
            "bool",
            0,
            (
                "bool",
                False,
            ),
        ),
        (
            "a_bool",
            "bool",
            1,
            (
                "bool",
                True,
            ),
        ),
        (
            "a_bool",
            "bool",
            32768,
            (
                "bool",
                True,
            ),
        ),
        (
            "a_bool",
            "bool",
            -1,
            (
                "bool",
                True,
            ),
        ),
        (
            "a_bool",
            "bool",
            b"\x01",
            (
                "bool",
                True,
            ),
        ),
        (
            "a_bool",
            "bool",
            b"\x00",
            (
                "bool",
                True,
            ),
        ),
        (
            "a_bool",
            "bool",
            "true",
            (
                "bool",
                True,
            ),
        ),
        (
            "a_bool",
            "bool",
            "false",
            (
                "bool",
                False,
            ),
        ),
        (
            "a_bool",
            "bool",
            "False",
            (
                "bool",
                False,
            ),
        ),
        (
            "a_bool",
            "bool",
            "1",
            (
                "bool",
                True,
            ),
        ),
        (
            "a_bool",
            "bool",
            "0",
            (
                "bool",
                False,
            ),
        ),
        (
            "an_address",
            "address",
            "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            (
                "address",
                "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            ),
        ),
        (
            "an_int16",
            "int16",
            -25,
            (
                "int16",
                -25,
            ),
        ),
        (
            "a_uint256",
            "uint256",
            1157920892373161954235709850086879078532699846656,
            (
                "uint256",
                1157920892373161954235709850086879078532699846656,
            ),
        ),
        (
            "empty_string",
            "string",
            "",
            (
                "bytes32",
                b"\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p",  # noqa: E501
            ),
        ),
        (
            "expected_sample",
            "Sample",
            {
                "name": "Cow",
            },
            (
                "bytes32",
                b"\x8flivK`W\xf4my$tFGG\x9f\x99k\xbe\xb9\x8e\xcfh]\xcb\x8b\x8ak\xb9\xe5\x17\xdd",  # noqa: E501
            ),
        ),
        (
            "expected_samples",
            "Samples",
            {
                "samples": [
                    {
                        "name": "Abe",
                    },
                    {
                        "name": "Bob",
                    },
                    {
                        "name": "Cow",
                    },
                ],
            },
            (
                "bytes32",
                b"\x94}\xef\x19'\xda\xc4\x1f\x85\xfb\x87ya\x8e\x1f\x87\x96L(\x80\\\xeb\t\xe6Gv8\x0c\x19k\\\t",  # noqa: E501
            ),
        ),
        (
            "some_bytes",
            "int256",
            "0xdeadbeef",
            (
                "int256",
                3735928559,
            ),
        ),
        (
            "some_string",
            "int16",
            "412",
            (
                "int16",
                412,
            ),
        ),
        (
            "some_int",
            "int",
            3735928559,
            (
                "int",
                3735928559,
            ),
        ),
        (
            "some_uint",
            "uint",
            412,
            (
                "uint",
                412,
            ),
        ),
        (
            "a_string_array",
            "string[]",
            [],
            (
                "bytes32",
                b"\xc5\xd2F\x01\x86\xf7#<\x92~}\xb2\xdc\xc7\x03\xc0\xe5\x00\xb6S\xca\x82';{\xfa\xd8\x04]\x85\xa4p",  # noqa: E501
            ),
        ),
        (
            "custom_type",
            "Samples",
            {"name": "bob", "samples": []},
            (
                "bytes32",
                b"(^\x89e\x13 \xa6\x16\xdf\r3\x1bOC\ngW\xb6\\\xb7\x1fn\x10\x8eh\xdc\x06\xa5\xd5\\\xc2\xb3",  # noqa: E501
            ),
        ),
    ),
    ids=[
        "None value for custom type",
        "None value for string type",
        "None value for bytes type",
        "string that is int-parseable value for bytes type",
        "int value for bytes type",
        "negative int value for bytes8 type coerces to 0 bytes8 value",
        "negative int value for bytes type coerces keccak(0) output",
        "hexstr value for bytes type",
        "bytes value for bytes type",
        "int value for string type",
        "string value for string type",
        "string[] value for string[] type",
        "string[][] value for string[][] type",
        "bool value False for bool type returns False",
        "bool value True for bool type returns True",
        "int value 0 for bool type returns False",
        "int value 1 for bool type returns True",
        "int value 37268 for bool type returns True",
        "int value -1 for bool type returns True",
        "bytes value b'\x01' for bool type returns True",
        "bytes value b'\x00' for bool type returns True",
        "string 'true' value for bool type returns True",
        "string 'false' value for bool type returns False",
        "string 'False' value for bool type returns False",
        "string '1' value for bool type returns True",
        "string '0' value for bool type returns False",
        "address value for address type",
        "int16 value for int16 type",
        "uint256 value for uint256 type",
        "empty string value for string type",
        "expected value for custom type",
        "expected value for custom type array",
        "hexstr value for int256 type",
        "str value for int16 type",
        "int value for int type",
        "int value for uint type",
        "empty array value for string[] type",
        "empty array value for custom[] type",
    ],
)
def test_encode_field_pass(name, type_, value, expected):
    types = {
        "Sample": [
            {"name": "name", "type": "string"},
        ],
        "Samples": [
            {"name": "samples", "type": "Sample[]"},
        ],
    }
    assert encode_field(types, name, type_, value) == expected


@pytest.mark.parametrize(
    "name, type_, value, expected",
    (
        (
            "atomic_type",
            "address",
            None,
            {
                "expected_exception": ValueError,
                "match": "Missing value for field `atomic_type` of type `address`",
            },
        ),
        (
            "non_int_string",
            "uint256",
            "i am not an int",
            {
                "expected_exception": ValueError,
                "match": re.escape(
                    "invalid literal for int() with base 10: 'i am not an int'"
                ),
            },
        ),
        (
            "non_hex_string",
            "uint256",
            "0xi am not an int",
            {
                "expected_exception": ValueError,
                "match": re.escape(
                    "invalid literal for int() with base 10: '0xi am not an int'"
                ),
            },
        ),
        (
            "a_string",
            "string",
            [],
            {
                "expected_exception": TypeError,
                "match": re.escape(
                    "Arguments passed as hexstr or text must be of text type. Instead, value was: []"  # noqa: E501
                ),
            },
        ),
        (
            "missing_inner_array",
            "string[][]",
            ["a", "b", "c"],
            {
                "expected_exception": ValueError,
                "match": re.escape(
                    "Invalid value for field `missing_inner_array` of type `string[]`: expected array, got `a` of type `<class 'str'>`"  # noqa: E501
                ),
            },
        ),
    ),
    ids=[
        "None value for atomic type",
        "string value that is not convertible to int for int type",
        "string starting with 0x that is not convertible to int for int type",
        "empty array value for string type",
        "string[] value for string[][] type",
    ],
)
def test_encode_field_fail(name, type_, value, expected):
    types = {
        "Sample": [
            {"name": "name", "type": "string"},
        ]
    }
    with pytest.raises(**expected):
        encode_field(types, name, type_, value)


@pytest.mark.parametrize(
    "primary_type, types, expected",
    (
        (
            "Person",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            {"Person"},
        ),
        (
            "Mail",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            {"Person", "Mail"},
        ),
        (
            "Person",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friend", "type": "Person"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            {"Person"},
        ),
        (
            "Mail",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friends", "type": "Person[]"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "attachments", "type": "Attachment[]"},
                ],
                "Attachment": [
                    {"name": "from", "type": "string"},
                ],
            },
            {"Person", "Mail", "Attachment"},
        ),
        (
            "Ma il!",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friends", "type": "Person"},
                ],
                "Ma il!": [
                    {"name": "from", "type": "Person"},
                    {"name": "attachments", "type": "Attachment[]"},
                ],
                "Attachment": [
                    {"name": "from", "type": "string"},
                ],
            },
            {"Person", "Ma il!", "Attachment"},
        ),
    ),
    ids=[
        "type with no dependencies",
        "type with one dependency",
        "type with recursive dependency",
        "type with array dependency",
        "type with non-alphanumeric in primary type",
    ],
)
def test_find_type_dependencies_pass(primary_type, types, expected):
    assert find_type_dependencies(primary_type, types) == expected


@pytest.mark.parametrize(
    "primary_type, types, expected",
    (
        (
            27,
            {
                27: [
                    {"name": "name", "type": "string"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            {
                "expected_exception": ValueError,
                "match": "Invalid find_type_dependencies input: expected string, "
                "got `27` of type `<class 'int'>`",
            },
        ),
        (
            "Person",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "pet", "type": "Animal"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            {
                "expected_exception": ValueError,
                "match": "No definition of type `Animal`",
            },
        ),
        (
            "Mail",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friends", "type": "Person[]"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "attachments", "type": "Attachment[]"},
                ],
            },
            {
                "expected_exception": ValueError,
                "match": "No definition of type `Attachment`",
            },
        ),
    ),
    ids=[
        "primary_type must be a string",
        "custom type in dependencies but not defined in types",
        "custom type array in dependencies but not defined in types",
    ],
)
def test_find_type_dependencies_fail(primary_type, types, expected):
    with pytest.raises(**expected):
        find_type_dependencies(primary_type, types)


@pytest.mark.parametrize(
    "primary_type, types, encode_type_expected, hash_type_expected",
    (
        (
            "Person",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            "Person(string name)",
            "fcbb73369ebb221abfdc626fdec0be9ca48ad89ef757b9a76eb7b31ddd261338",
        ),
        (
            "Mail",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            "Mail(Person from)Person(string name)",
            "979fb836e7a3c69210ec4cfec014139732f26442be0f5c10c4222ccabfe6a025",
        ),
        (
            "Person",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friend", "type": "Person"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            "Person(string name,Person friend)",
            "945f8587e8daf26c14c625b054bfccb52dc48747984b7925c0901efca7186e14",
        ),
        (
            "Mail",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friends", "type": "Person[]"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "attachments", "type": "Attachment[]"},
                ],
                "Attachment": [
                    {"name": "from", "type": "string"},
                ],
            },
            "Mail(Person from,Attachment[] attachments)Attachment(string from)Person(string name,Person[] friends)",  # noqa: E501
            "0c555dd4d869769a9f68c39860155342ea7e75a215669bc44efca1b4544735e5",
        ),
        (
            "Ma il!",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friends", "type": "Person"},
                ],
                "Ma il!": [
                    {"name": "from", "type": "Person"},
                    {"name": "attachments", "type": "Attachment[]"},
                ],
                "Attachment": [
                    {"name": "from", "type": "string"},
                ],
            },
            "Ma il!(Person from,Attachment[] attachments)Attachment(string from)Person(string name,Person friends)",  # noqa: E501
            "099b05cabe783f37d88d94e349693aca4fc9ae40c51e5d2640ff040768e5b2ad",
        ),
    ),
    ids=[
        "type with no dependencies",
        "type with one dependency",
        "type with recursive dependency",
        "type with array dependency",
        "type with non-alphanumeric in primary type",
    ],
)
def test_encode_type_pass_and_hash_type(
    primary_type, types, encode_type_expected, hash_type_expected
):
    assert encode_type(primary_type, types) == encode_type_expected
    assert hash_type(primary_type, types).hex() == hash_type_expected


@pytest.mark.parametrize(
    "primary_type, types, expected",
    (
        (
            "Mail",
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "friends", "type": "Person[]"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "attachments", "type": "Attachment[]"},
                ],
            },
            {
                "expected_exception": ValueError,
                "match": "No definition of type `Attachment`",
            },
        ),
    ),
    ids=[
        "custom type array in dependencies but not defined in types",
    ],
)
def test_encode_type_fail(primary_type, types, expected):
    with pytest.raises(**expected):
        encode_type(primary_type, types)


@pytest.mark.parametrize(
    "domain_data, expected",
    (
        (
            {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            },
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
        ),
        (
            {
                "name": "Ether Mail",
                "version": "1",
                "chainId": "1",
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            },
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
        ),
        (
            {
                "name": "Ether Mail",
                "version": 1,
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            },
            "902f609607aa38e1c768f260a84a1be97f3a9d65726d3e842fa5e36c6da393cb",
        ),
        (
            {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xcccccccccccccccccccccccccccccccccccccccc",
            },
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f",
        ),
        (
            {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
                "salt": "0xa9f4c8b7e576dc96308c361b46d32c04a00a0e5c2b0962d9f42be6891a95d139",  # noqa: E501
            },
            "53d039704f24ce448de9dc98c5952dd85b7e7c22446a0b1cb47b43b901d00972",
        ),
        (
            {},
            "6192106f129ce05c9075d319c1fa6ea9b3ae37cbd0c1ef92e2be7137bb07baa1",
        ),
    ),
    ids=[
        "EIP712 example domain data",
        "chainId as string",
        "version as int",
        "verifying contract not checksummed",
        "salt present but empty bytes",
        "empty domain data",
    ],
)
def test_hash_domain_pass(domain_data, expected):
    assert hash_domain(domain_data).hex() == expected


@pytest.mark.parametrize(
    "domain_data, expected",
    (
        (
            {
                "name": "Ether Mail",
                "classification": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            },
            {
                "expected_exception": ValueError,
                "match": "Invalid domain key: `classification`",
            },
        ),
        (
            {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCC",
            },
            {
                "expected_exception": EncodingTypeError,
                "match": "Value `'0xCcCCccccCCCC'` of type <class 'str'> cannot be encoded by AddressEncoder",  # noqa: E501
            },
        ),
    ),
    ids=[
        "key in domain_data not in EIP712 domain fields",
        "invalid address for verifyingContract",
    ],
)
def test_hash_domain_fail(domain_data, expected):
    with pytest.raises(**expected):
        hash_domain(domain_data)


@pytest.mark.parametrize(
    "type_,message, types, encode_data_expected, hash_struct_expected",
    (
        (
            "Mail",
            {
                "from": {
                    "name": "Cow",
                },
            },
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                ],
            },
            "979fb836e7a3c69210ec4cfec014139732f26442be0f5c10c4222ccabfe6a025bfb54ec5e6bf391ea339a110356cb0fd003296b0dabe4b0b2e51d0e50c815c8a",  # noqa: E501
            "dfa5fd27fea278587b6c6a56d8e6cf2853b6698a4244afc1f5f526f04b2b70b3",
        ),
        (
            "People",
            {
                "who": [
                    {
                        "name": "Cow",
                    },
                    {
                        "name": "Dan",
                    },
                    {
                        "name": "Eve",
                    },
                ],
            },
            {
                "Person": [
                    {"name": "name", "type": "string"},
                ],
                "People": [
                    {"name": "who", "type": "Person[]"},
                ],
            },
            "cd6dded05d140e80a24f1b3f8ec7635be0235a2bb1ac5acc4f6a8c0e81959c1fdd333db219c66d1b097970cebde115462698f9bfe6ea7497898a67c7da923d33",  # noqa: E501
            "978fbd13a22cb2ced753b88943583080d6e2fa20d9f5818181dd85ee26438745",
        ),
        (
            "Things",
            {
                "what": [
                    [
                        {
                            "name": "Cow",
                        },
                    ],
                    [
                        {
                            "name": "Dan",
                        },
                    ],
                    [
                        {
                            "name": "Eve",
                        },
                    ],
                ],
            },
            {
                "Stuff": [
                    {"name": "name", "type": "string"},
                ],
                "Things": [
                    {"name": "what", "type": "Stuff[][]"},
                ],
            },
            "888cc41f0207f14b9f9e8dbaeb2cedc28dcd62ea4bd2d68c81ebb1416c846e63676cc832675b2d6ab9eb44e83f08c0df303bf2771036d926ed6fb385b6ee6de0",  # noqa: E501
            "b475420217c60fe1a7ad38c925c80f5d2c58e0fbb980684e4722f810ba9235d8",
        ),
        (
            "Things",
            {
                "what": [
                    [
                        {
                            "name": "Cow",
                        },
                    ],
                    [
                        {
                            "name": "Dan",
                        },
                    ],
                    [
                        {
                            "name": "Eve",
                        },
                    ],
                ],
            },
            {
                "Stuff": [
                    {"name": "name", "type": "string"},
                ],
                "Things": [
                    {"name": "what", "type": "Stuff[3][1]"},
                ],
            },
            "0e1a553943c15cc6227e8a3d2c788d3e74b25f85f30be99bfc6228e404e79fb9676cc832675b2d6ab9eb44e83f08c0df303bf2771036d926ed6fb385b6ee6de0",  # noqa: E501
            "cdbacf00da86992e9443d46aa0206e27d670a6140155f8c505a68ba733c7e639",
        ),
        (
            "Things",
            {
                "what": [
                    [
                        {
                            "name": "Cow",
                        },
                    ],
                    [
                        {
                            "name": "Dan",
                        },
                    ],
                    [
                        {
                            "name": "Eve",
                        },
                    ],
                ],
            },
            {
                "Stuff": [
                    {"name": "name", "type": "string"},
                ],
                "Things": [
                    {"name": "what", "type": "Stuff[8][5]"},
                ],
            },
            "5e38f404f170c80d6c941310101dfad8882e50828efc75c104c7675960b4cc94676cc832675b2d6ab9eb44e83f08c0df303bf2771036d926ed6fb385b6ee6de0",  # noqa: E501
            "ed3eb2f09fad610e8805f43a34704858e1ad7f3cd12b61e712b402be370b9001",
        ),
        (
            "Things",
            {
                "what": b"1234567890abcdef",
            },
            {
                "Things": [
                    {"name": "what", "type": "bytes16"},
                ],
            },
            "b093a949c507c3814cc23da9eebb03679633e22cec8c8633c878f43b025201333132333435363738393061626364656600000000000000000000000000000000",  # noqa: E501
            "6825950a843718a846bf289599316a041180fd20d942ae0ca6106396ff797655",
        ),
    ),
    ids=[
        "primary type with one custom type dependency",
        "primary type with one custom type array dependency",
        "primary type with one custom type nested array dependency",
        "encodes when data matches defined array size",
        "encodes when data does not match defined array size",
        "bytes8 value for bytes16 type",
    ],
)
def test_encode_data_pass_and_hash_struct_and_hash_eip712_message(
    type_,
    message,
    types,
    encode_data_expected,
    hash_struct_expected,
):
    assert encode_data(type_, types, message).hex() == encode_data_expected
    assert hash_struct(type_, types, message).hex() == hash_struct_expected
    assert hash_eip712_message(types, message).hex() == hash_struct_expected


@pytest.mark.parametrize(
    "type_,message, types, expected_error",
    (
        (
            "Things",
            {
                "what": -327,
            },
            {
                "Things": [
                    {"name": "what", "type": "uint"},
                ],
            },
            {
                "expected_exception": ValueOutOfBounds,
                "match": re.escape(
                    "Value `-327` of type <class 'int'> cannot be encoded by UnsignedIntegerEncoder: Cannot be encoded in 256 bits. Must be bounded between [0, 115792089237316195423570985008687907853269984665640564039457584007913129639935]."  # noqa: E501
                ),
            },
        ),
        (
            "Things",
            {
                "what": b"1234567890abcdef1234567890abcdef",
            },
            {
                "Things": [
                    {"name": "what", "type": "bytes8"},
                ],
            },
            {
                "expected_exception": ValueOutOfBounds,
                "match": "Value `b'1234567890abcdef1234567890abcdef'` of type <class "
                "'bytes'> cannot be encoded by BytesEncoder: exceeds total "
                "byte size for bytes8 encoding",
            },
        ),
        (
            "Things",
            {
                "what": 4294967295,
            },
            {
                "Things": [
                    {"name": "what", "type": "int16"},
                ],
            },
            {
                "expected_exception": ValueOutOfBounds,
                "match": re.escape(
                    "Value `4294967295` of type <class 'int'> cannot be encoded by SignedIntegerEncoder: Cannot be encoded in 16 bits. Must be bounded between [-32768, 32767]."  # noqa: E501
                ),
            },
        ),
        (
            "Things",
            {
                "what": "0xdeadbeef",
            },
            {
                "Things": [
                    {"name": "what", "type": "address"},
                ],
            },
            {
                "expected_exception": EncodingTypeError,
                "match": re.escape(
                    "Value `'0xdeadbeef'` of type <class 'str'> cannot be encoded by AddressEncoder",  # noqa: E501
                ),
            },
        ),
        (
            "Things",
            {
                "what": "deadbeef",
            },
            {
                "Things": [
                    {"name": "what", "type": "int256"},
                ],
            },
            {
                "expected_exception": ValueError,
                "match": re.escape(
                    "invalid literal for int() with base 10: 'deadbeef",
                ),
            },
        ),
    ),
    ids=[
        "negative value -327 for uint type",
        "bytes16 value for bytes8 type",
        "int value too large for int16 type",
        "hexstring too short to be an address",
        "hexstring must have 0x prefix be parsed as int",
    ],
)
def test_encode_data_fail(type_, message, types, expected_error):
    with pytest.raises(**expected_error):
        encode_data(type_, types, message)


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
def test_encode_field_bool_with_unhashable_value(value, expected):
    assert encode_field({}, "enabled", "bool", value) == ("bool", expected)
