import pytest
import os

from eth_keyfile.keyfile import (
    get_default_work_factor_for_kdf,
)
from eth_keys import (
    keys,
)
from eth_keys.backends import (
    NativeECCBackend,
)
from eth_utils import (
    is_checksum_address,
    to_bytes,
    to_checksum_address,
    to_hex,
    to_int,
)
from eth_utils.toolz import (
    dissoc,
)
from hexbytes import (
    HexBytes,
)
from hypothesis import (
    given,
    strategies as st,
)

from eth_account import (
    Account,
)
from eth_account.messages import (
    defunct_hash_message,
    encode_defunct,
    encode_intended_validator,
    encode_typed_data,
)
from tests.eip712_messages import (
    ALL_VALID_EIP712_MESSAGES,
)

# from https://github.com/ethereum/tests/blob/3930ca3a9a377107d5792b3e7202f79c688f1a67/BasicTests/txtest.json # noqa: E501
ETH_TEST_TRANSACTIONS = [
    {
        "chainId": None,
        "key": "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
        "nonce": 0,
        "gasPrice": 1000000000000,
        "gas": 10000,
        "to": "0x13978aee95f38490e9769C39B2773Ed763d9cd5F",
        "value": 10000000000000000,
        "data": "",
        "unsigned": "eb8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc1000080808080",  # noqa: E501
        "signed": "f86b8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc10000801ba0eab47c1a49bf2fe5d40e01d313900e19ca485867d462fe06e139e3a536c6d4f4a014a569d327dcda4b29f74f93c0e9729d2f49ad726e703f9cd90dbb0fbf6649f1",  # noqa: E501
    },
    {
        "chainId": None,
        "key": "c87f65ff3f271bf5dc8643484f66b200109caffe4bf98c4cb393dc35740b28c0",
        "nonce": 0,
        "gasPrice": 1000000000000,
        "gas": 10000,
        "to": "",
        "value": 0,
        "data": "6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f2",  # noqa: E501
        "unsigned": "f83f8085e8d4a510008227108080af6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f2808080",  # noqa: E501
        "signed": "f87f8085e8d4a510008227108080af6025515b525b600a37f260003556601b596020356000355760015b525b54602052f260255860005b525b54602052f21ba05afed0244d0da90b67cf8979b0f246432a5112c0d31e8d5eedd2bc17b171c694a0bb1035c834677c2e1185b8dc90ca6d1fa585ab3d7ef23707e1a497a98e752d1b",  # noqa: E501
    },
    {
        "chainId": None,
        "key": "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
        "nonce": 0,
        "gasPrice": 1000000000000,
        "gas": 10000,
        "to": HexBytes("0x13978aee95f38490e9769C39B2773Ed763d9cd5F"),
        "value": 10000000000000000,
        "data": "",
        "unsigned": "eb8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc1000080808080",  # noqa: E501
        "signed": "f86b8085e8d4a510008227109413978aee95f38490e9769c39b2773ed763d9cd5f872386f26fc10000801ba0eab47c1a49bf2fe5d40e01d313900e19ca485867d462fe06e139e3a536c6d4f4a014a569d327dcda4b29f74f93c0e9729d2f49ad726e703f9cd90dbb0fbf6649f1",  # noqa: E501
    },
    # Typed Transaction (EIP-2930's access list transaction) - empty list.
    {
        "key": "fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19",
        "gas": "0x186a0",
        "gasPrice": "0x3b9aca00",
        "data": "0x616263646566",
        "nonce": "0x27",
        "to": "0x09616C3d61b3331fc4109a9E41a8BDB7d9776609",
        "value": "0x5af3107a4000",
        "type": "0x1",
        "accessList": [],
        "chainId": "0x76c",
        "signed": "0x01f87482076c27843b9aca00830186a09409616c3d61b3331fc4109a9e41a8bdb7d9776609865af3107a400086616263646566c080a0bad1a40fa2d90dc7539831bb82dfccf9b7094eab238d50c4369b805fb7241c58a046ab7eb7ff8cdfd203847b7e1b2f9e41208bba76a86ae3eeb97fe2727763aa12",  # noqa: E501
    },
    # Typed Transaction (EIP-2930's access list transaction) - non-empty list.
    {
        "key": "fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19",
        "gas": "0x186a0",
        "gasPrice": "0x3b9aca00",
        "data": "0x616263646566",
        "nonce": "0x22",
        "to": "0x09616C3d61b3331fc4109a9E41a8BDB7d9776609",
        "value": "0x5af3107a4000",
        "type": "0x1",
        "accessList": [
            {
                "address": "0x0000000000000000000000000000000000000001",
                "storageKeys": [
                    "0x0100000000000000000000000000000000000000000000000000000000000000"
                ],
            },
        ],
        "chainId": "0x76c",
        "signed": "0x01f8ad82076c22843b9aca00830186a09409616c3d61b3331fc4109a9e41a8bdb7d9776609865af3107a400086616263646566f838f7940000000000000000000000000000000000000001e1a0010000000000000000000000000000000000000000000000000000000000000001a08289e85fa00f8f7f78a53cf147a87b2a7f0d27e64d7571f9d06a802e365c3430a017dc77eae36c88937db4a5179f57edc6119701652f3f1c6f194d1210d638a061",  # noqa: E501
    },
    # Typed Transaction (EIP-1559's dynamic fee transaction)
    {
        "key": "70af7ec25374c2b06cbfffeaf9817a3d1bc61854abbf39e9e00de734b0c0c8c4",
        "gas": "0x186a0",
        "maxFeePerGas": "0x77359400",
        "maxPriorityFeePerGas": "0x77359400",
        "data": "0x5544",
        "nonce": "0x2",
        "to": "0x96216849c49358B10257cb55b28eA603c874b05E",
        "value": "0x5af3107a4000",
        "type": "0x2",
        "chainId": "0x539",
        "signed": "0x02f8758205390284773594008477359400830186a09496216849c49358b10257cb55b28ea603c874b05e865af3107a4000825544c001a008badd022b23e5bb51a13a18c99185dbd24aac054f876a3cf89a61672e998b89a01d14fb34a688d516f6444fdb6ceca7778be786cc70d3fa29714b6f232f09a83a",  # noqa: E501
    },
    # Typed Transaction (EIP-1559's dynamic fee transaction) -
    # integer values and access list
    {
        "key": "70af7ec25374c2b06cbfffeaf9817a3d1bc61854abbf39e9e00de734b0c0c8c4",
        "gas": 100000,
        "maxFeePerGas": 2000000000,
        "maxPriorityFeePerGas": 1000000000,
        "data": "0x5544",
        "nonce": "0x2",
        "to": "0x96216849c49358B10257cb55b28eA603c874b05E",
        "value": "0x5af3107a4000",
        "type": "0x2",
        "accessList": [
            {
                "address": "0x0000000000000000000000000000000000000001",
                "storageKeys": [
                    "0x0100000000000000000000000000000000000000000000000000000000000000"
                ],
            },
        ],
        "chainId": "0x539",
        "signed": "0x02f8ae82053902843b9aca008477359400830186a09496216849c49358b10257cb55b28ea603c874b05e865af3107a4000825544f838f7940000000000000000000000000000000000000001e1a0010000000000000000000000000000000000000000000000000000000000000001a036727d3bb8339377ac1d4c8b4d8c684a75d36047ebc369628be8d4d0f962d70ea064b1a8d2568bb9c44290242e8af47e1f428e2bf3073d9822a753649247321dfc",  # noqa: E501
    },
]


PRIVATE_KEY_AS_BYTES = b"unicorns" * 4
PRIVATE_KEY_AS_HEXSTR = (
    "0x756e69636f726e73756e69636f726e73756e69636f726e73756e69636f726e73"
)
PRIVATE_KEY_AS_INT = 0x756E69636F726E73756E69636F726E73756E69636F726E73756E69636F726E73
PRIVATE_KEY_AS_OBJ = keys.PrivateKey(PRIVATE_KEY_AS_BYTES)
ACCT_ADDRESS = "0xa79F6f349C853F9Ea0B29636779ae3Cb4E3BA729"

PRIVATE_KEY_AS_BYTES_ALT = b"rainbows" * 4
PRIVATE_KEY_AS_HEXSTR_ALT = (
    "0x7261696e626f77737261696e626f77737261696e626f77737261696e626f7773"
)
PRIVATE_KEY_AS_INT_ALT = (
    0x7261696E626F77737261696E626F77737261696E626F77737261696E626F7773
)
PRIVATE_KEY_AS_OBJ_ALT = keys.PrivateKey(PRIVATE_KEY_AS_BYTES_ALT)
ACCT_ADDRESS_ALT = "0xafd7f0E16A1814B854b45f551AFD493BE5F039F9"


class TrackingBackend(NativeECCBackend):
    sign_calls = 0

    def ecdsa_sign(self, msg_hash, private_key):
        type(self).sign_calls += 1
        return super().ecdsa_sign(msg_hash, private_key)

    @classmethod
    def reset(cls):
        cls.sign_calls = 0


@pytest.fixture(
    params=[
        PRIVATE_KEY_AS_INT,
        PRIVATE_KEY_AS_HEXSTR,
        PRIVATE_KEY_AS_BYTES,
        PRIVATE_KEY_AS_OBJ,
    ]
)  # noqa: E501
def PRIVATE_KEY(request):
    return request.param


@pytest.fixture(
    params=[
        PRIVATE_KEY_AS_INT_ALT,
        PRIVATE_KEY_AS_HEXSTR_ALT,
        PRIVATE_KEY_AS_BYTES_ALT,
        PRIVATE_KEY_AS_OBJ_ALT,
    ]
)  # noqa: E501
def PRIVATE_KEY_ALT(request):
    return request.param


@pytest.fixture(params=["instance", "class"])
def acct(request):
    if request.param == "instance":
        return Account()
    elif request.param == "class":
        return Account
    else:
        raise Exception(f"account invocation {request.param} is not supported")


@pytest.fixture(scope="module")
def keyed_acct():
    return Account.from_key(PRIVATE_KEY_AS_BYTES)


@pytest.fixture(params=("text", "primitive", "hexstr"))
def message_encodings(request):
    if request == "text":
        return {"text": "hello world"}
    elif request == "primitive":
        return {"primitive": b"hello world"}
    else:
        return {"hexstr": "68656c6c6f20776f726c64"}


def test_eth_account_default_kdf(acct, monkeypatch):
    assert os.getenv("ETH_ACCOUNT_KDF") is None
    assert acct._default_kdf == "scrypt"

    monkeypatch.setenv("ETH_ACCOUNT_KDF", "pbkdf2")
    assert os.getenv("ETH_ACCOUNT_KDF") == "pbkdf2"

    import importlib

    from eth_account import (
        account,
    )

    importlib.reload(account)
    assert account.Account._default_kdf == "pbkdf2"


def test_eth_account_create_variation(acct):
    account1 = acct.create()
    account2 = acct.create()
    assert account1 != account2


def test_eth_account_equality(acct, PRIVATE_KEY):
    acct1 = acct.from_key(PRIVATE_KEY)
    acct2 = acct.from_key(PRIVATE_KEY)
    assert acct1 == acct2


def test_eth_account_from_key_reproducible(acct, PRIVATE_KEY):
    account1 = acct.from_key(PRIVATE_KEY)
    account2 = acct.from_key(PRIVATE_KEY)
    assert bytes(account1) == PRIVATE_KEY_AS_BYTES
    assert bytes(account1) == bytes(account2)
    assert isinstance(str(account1), str)


def test_eth_account_from_key_diverge(acct, PRIVATE_KEY, PRIVATE_KEY_ALT):
    account1 = acct.from_key(PRIVATE_KEY)
    account2 = acct.from_key(PRIVATE_KEY_ALT)
    assert bytes(account2) == PRIVATE_KEY_AS_BYTES_ALT
    assert bytes(account1) != bytes(account2)


def test_eth_account_from_key_seed_restrictions(acct):
    with pytest.raises(ValueError):
        acct.from_key(b"")
    with pytest.raises(ValueError):
        acct.from_key(b"\xff" * 31)
    with pytest.raises(ValueError):
        acct.from_key(b"\xff" * 33)


def test_eth_account_from_key_properties(acct, PRIVATE_KEY):
    account = acct.from_key(PRIVATE_KEY)
    assert callable(account.sign_transaction)
    assert callable(account.sign_message)
    assert is_checksum_address(account.address)
    assert account.address == ACCT_ADDRESS
    assert account.key == PRIVATE_KEY_AS_OBJ


def test_eth_account_create_properties(acct):
    account = acct.create()
    assert callable(account.sign_transaction)
    assert callable(account.sign_message)
    assert is_checksum_address(account.address)
    assert isinstance(account.key, bytes) and len(account.key) == 32


def test_eth_account_recover_transaction_example(acct):
    raw_tx_hex = "0xf8640d843b9aca00830e57e0945b2063246f2191f18f2675cedb8b28102e957458018025a00c753084e5a8290219324c1a3a86d4064ded2d15979b1ea790734aaa2ceaafc1a0229ca4538106819fd3a5509dd383e8fe4b731c6870339556a5c06feb9cf330bb"  # noqa: E501
    from_account = acct.recover_transaction(raw_tx_hex)
    assert from_account == "0xFeC2079e80465cc8C687fFF9EE6386ca447aFec4"


def test_eth_account_recover_transaction_with_literal(acct):
    raw_tx = 0xF8640D843B9ACA00830E57E0945B2063246F2191F18F2675CEDB8B28102E957458018025A00C753084E5A8290219324C1A3A86D4064DED2D15979B1EA790734AAA2CEAAFC1A0229CA4538106819FD3A5509DD383E8FE4B731C6870339556A5C06FEB9CF330BB  # noqa: E501
    from_account = acct.recover_transaction(raw_tx)
    assert from_account == "0xFeC2079e80465cc8C687fFF9EE6386ca447aFec4"


def test_eth_account_recover_message(acct):
    v, r, s = (
        28,
        "0xe6ca9bba58c88611fad66a6ce8f996908195593807c4b38bd528d2cff09d4eb3",
        "0x3e5bfbbf4d3e39b1a2fd816a7680c19ebebaf3a141b239934ad43cb33fcec8ce",
    )
    message_text = "I♥SF"
    message = encode_defunct(text=message_text)
    from_account = acct.recover_message(message, vrs=(v, r, s))
    assert from_account == "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"


@pytest.mark.parametrize(
    "signature_bytes",
    [
        # test signature bytes with standard v (0 in this case)
        b"\0Q[\xc8\xfd2&N!\xec\x08 \xe8\xc5\x12>\xd5\x8c\x11\x95\xc9\xea\x17\xcb\x01\x8b\x1a\xd4\x07<\xc5\xa6\0\x80\xf5\xdc\xec9zZ\x8cR0\x82\xbf\xa4\x17qV\x89\x03\xaaUN\xc0k\xa8G\\\xa9\x05\x0f\xb7\xd5\x00",  # noqa: E501
        # test signature bytes with chain-naive v (27 in this case)
        b"\0Q[\xc8\xfd2&N!\xec\x08 \xe8\xc5\x12>\xd5\x8c\x11\x95\xc9\xea\x17\xcb\x01\x8b\x1a\xd4\x07<\xc5\xa6\0\x80\xf5\xdc\xec9zZ\x8cR0\x82\xbf\xa4\x17qV\x89\x03\xaaUN\xc0k\xa8G\\\xa9\x05\x0f\xb7\xd5\x1b",  # noqa: E501
    ],
    ids=["test_sig_bytes_standard_v", "test_sig_bytes_chain_naive_v"],
)
def test_eth_account_recover_signature_bytes(acct, signature_bytes):
    # found a signature with a leading 0 byte in both r and s
    message = encode_defunct(text="10284")
    from_account = acct.recover_message(message, signature=signature_bytes)
    assert from_account == "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"


@pytest.mark.parametrize("raw_v", (0, 27))
@pytest.mark.parametrize("as_hex", (False, True))
def test_eth_account_recover_vrs(acct, raw_v, as_hex):
    # found a signature with a leading 0 byte in both r and s
    raw_r, raw_s = (
        143748089818580655331728101695676826715814583506606354117109114714663470502,
        227853308212209543997879651656855994238138056366857653269155208245074180053,
    )
    if as_hex:
        vrs = map(to_hex, (raw_v, raw_r, raw_s))
    else:
        vrs = raw_v, raw_r, raw_s

    message = encode_defunct(text="10284")
    from_account = acct.recover_message(message, vrs=vrs)
    assert from_account == "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"


@pytest.mark.parametrize(
    "message, expected",
    [
        (
            "Message tö sign. Longer than hash!",
            HexBytes(
                "0x10c7cb57942998ab214c062e7a57220a174aacd80418cead9f90ec410eacada1"
            ),
        ),
        (
            # Intentionally sneaky: message is a hexstr interpreted as text
            "0x4d6573736167652074c3b6207369676e2e204c6f6e676572207468616e206861736821",
            HexBytes(
                "0x6192785e9ad00100e7332ff585824b65eafa30bc8f1265cf86b5368aa3ab5d56"
            ),
        ),
        (
            "Hello World",
            HexBytes(
                "0xa1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
            ),
        ),
    ],
    ids=["message_to_sign", "hexstr_as_text", "hello_world"],
)
def test_eth_account_hash_message_text(message, expected):
    assert defunct_hash_message(text=message) == expected


@pytest.mark.parametrize(
    "message, expected",
    [
        (
            "0x4d6573736167652074c3b6207369676e2e204c6f6e676572207468616e206861736821",
            HexBytes(
                "0x10c7cb57942998ab214c062e7a57220a174aacd80418cead9f90ec410eacada1"
            ),
        ),
        (
            "0x29d9f7d6a1d1e62152f314f04e6bd4300ad56fd72102b6b83702869a089f470c",
            HexBytes(
                "0xe709159ef0e6323c705786fc50e47a8143812e9f82f429e585034777c7bf530b"
            ),
        ),
    ],
    ids=["hexbytes_1", "hexbytes_2"],
)
def test_eth_account_hash_message_hexstr(acct, message, expected):
    assert defunct_hash_message(hexstr=message) == expected


@given(st.text())
def test_sign_message_against_sign_hash_as_text(keyed_acct, message_text):
    # sign via hash
    msg_hash = defunct_hash_message(text=message_text)
    signed_via_hash = keyed_acct.unsafe_sign_hash(msg_hash)

    # sign via message
    signable_message = encode_defunct(text=message_text)
    signed_via_message = keyed_acct.sign_message(signable_message)
    assert signed_via_hash == signed_via_message


@given(st.binary())
def test_sign_message_against_sign_hash_as_bytes(keyed_acct, message_bytes):
    # sign via hash
    msg_hash = defunct_hash_message(message_bytes)
    signed_via_hash = keyed_acct.unsafe_sign_hash(msg_hash)

    # sign via message
    signable_message = encode_defunct(message_bytes)
    signed_via_message = keyed_acct.sign_message(signable_message)

    assert signed_via_hash == signed_via_message


@given(st.binary())
def test_sign_message_against_sign_hash_as_hex(keyed_acct, message_bytes):
    message_hex = to_hex(message_bytes)

    # sign via hash
    msg_hash_hex = defunct_hash_message(hexstr=message_hex)
    signed_via_hash_hex = keyed_acct.unsafe_sign_hash(msg_hash_hex)

    # sign via message
    signable_message_hex = encode_defunct(hexstr=message_hex)
    signed_via_message_hex = keyed_acct.sign_message(signable_message_hex)

    assert signed_via_hash_hex == signed_via_message_hex


@pytest.mark.parametrize(
    "message, key, expected_bytes, expected_hash, v, r, s, signature",
    (
        (
            "Some data",
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
            b"Some data",
            HexBytes(
                "0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"
            ),
            28,
            83713930994764734002432606962255364472443135907807238282514898577139886061053,  # noqa: E501
            43435997768575461196683613590576722655951133545204789519877940758262837256233,  # noqa: E501
            HexBytes(
                "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"  # noqa: E501
            ),
        ),
        (
            "Some data",
            keys.PrivateKey(
                HexBytes(
                    "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                )
            ),
            b"Some data",
            HexBytes(
                "0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"
            ),
            28,
            83713930994764734002432606962255364472443135907807238282514898577139886061053,  # noqa: E501
            43435997768575461196683613590576722655951133545204789519877940758262837256233,  # noqa: E501
            HexBytes(
                "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"  # noqa: E501
            ),
        ),
        (
            "10284",
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
            b"10284",
            HexBytes(
                "0x0a162a5efbba02f38db3114531c8acba39fe676f09f7e471d93e8a06c471821c"
            ),
            27,
            143748089818580655331728101695676826715814583506606354117109114714663470502,
            227853308212209543997879651656855994238138056366857653269155208245074180053,
            HexBytes(
                "0x00515bc8fd32264e21ec0820e8c5123ed58c1195c9ea17cb018b1ad4073cc5a60080f5dcec397a5a8c523082bfa41771568903aa554ec06ba8475ca9050fb7d51b"  # noqa: E501
            ),
        ),
    ),
    ids=[
        "web3js_hex_str_example",
        "web3js_eth_keys.datatypes.PrivateKey_example",
        "31byte_r_and_s",
    ],
)
def test_eth_account_sign(
    acct, message, key, expected_bytes, expected_hash, v, r, s, signature
):
    signable = encode_defunct(text=message)
    signed = acct.sign_message(signable, private_key=key)
    assert signed.message_hash == signed["message_hash"] == expected_hash
    assert signed.v == signed["v"] == v
    assert signed.r == signed["r"] == r
    assert signed.s == signed["s"] == s
    assert signed.signature == signed["signature"] == signature

    account = acct.from_key(key)
    assert account.sign_message(signable) == signed


def test_eth_valid_account_address_sign_data_with_intended_validator(
    acct, message_encodings
):
    account = acct.create()
    signable = encode_intended_validator(
        account.address,
        **message_encodings,
    )
    signed = account.sign_message(signable)
    signed_classmethod = acct.sign_message(signable, account.key)
    assert signed == signed_classmethod
    new_addr = acct.recover_message(signable, signature=signed.signature)
    assert new_addr == account.address


def test_eth_short_account_address_sign_data_with_intended_validator(
    acct, message_encodings
):
    account = acct.create()

    address_in_bytes = to_bytes(hexstr=account.address)
    # Test for all lengths of addresses < 20 bytes
    for i in range(1, 21):
        with pytest.raises(TypeError):
            # Raise TypeError if the address is less than 20 bytes
            defunct_hash_message(
                **message_encodings,
                signature_version=b"\x00",
                version_specific_data=to_hex(address_in_bytes[:-i]),
            )


def test_eth_long_account_address_sign_data_with_intended_validator(
    acct, message_encodings
):
    account = acct.create()

    address_in_bytes = to_bytes(hexstr=account.address)
    with pytest.raises(TypeError):
        # Raise TypeError if the address is more than 20 bytes
        defunct_hash_message(
            **message_encodings,
            signature_version=b"\x00",
            version_specific_data=to_hex(address_in_bytes + b"\x00"),
        )


@pytest.mark.parametrize(
    "txn, private_key, expected_raw_tx, tx_hash, r, s, v",
    (
        (
            {
                "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                "value": 1000000000,
                "gas": 2000000,
                "gasPrice": 234567897654321,
                "nonce": 0,
                "chainId": 1,
            },
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
            HexBytes(
                "0xf86a8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca008025a009ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9ca0440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428"  # noqa: E501
            ),
            HexBytes(
                "0xd8f64a42b57be0d565f385378db2f6bf324ce14a594afc05de90436e9ce01f60"
            ),
            4487286261793418179817841024889747115779324305375823110249149479905075174044,  # noqa: E501
            30785525769477805655994251009256770582792548537338581640010273753578382951464,  # noqa: E501
            37,
        ),
        (
            {
                "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                "value": 1000000000,
                "gas": 2000000,
                "gasPrice": 234567897654321,
                "nonce": 0,
                "chainId": 1,
            },
            keys.PrivateKey(
                HexBytes(
                    "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                )
            ),  # noqa: E501
            HexBytes(
                "0xf86a8086d55698372431831e848094f0109fc8df283027b6285cc889f5aa624eac1f55843b9aca008025a009ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9ca0440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428"  # noqa: E501
            ),
            HexBytes(
                "0xd8f64a42b57be0d565f385378db2f6bf324ce14a594afc05de90436e9ce01f60"
            ),
            4487286261793418179817841024889747115779324305375823110249149479905075174044,  # noqa: E501
            30785525769477805655994251009256770582792548537338581640010273753578382951464,  # noqa: E501
            37,
        ),
        (
            {
                "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                "value": 0,
                "gas": 31853,
                "gasPrice": 0,
                "nonce": 0,
                "chainId": 1,
            },
            "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
            HexBytes(
                "0xf85d8080827c6d94f0109fc8df283027b6285cc889f5aa624eac1f558080269f22f17b38af35286ffbb0c6376c86ec91c20ecbad93f84913a0cc15e7580cd99f83d6e12e82e3544cb4439964d5087da78f74cefeec9a450b16ae179fd8fe20"  # noqa: E501
            ),
            HexBytes(
                "0xb0c5e2c6b29eeb0b9c1d63eaa8b0f93c02ead18ae01cb7fc795b0612d3e9d55a"
            ),
            61739443115046231975538240097110168545680205678104352478922255527799426265,
            232940010090391255679819602567388136081614408698362277324138554019997613600,
            38,
        ),
        (
            {
                "gas": "0x186a0",
                "gasPrice": "0x3b9aca00",
                "data": "0x616263646566",
                "nonce": "0x22",
                "to": "0x09616C3d61b3331fc4109a9E41a8BDB7d9776609",
                "value": "0x5af3107a4000",
                "type": "0x1",
                "accessList": [
                    {
                        "address": "0x0000000000000000000000000000000000000001",
                        "storageKeys": [
                            "0x0100000000000000000000000000000000000000000000000000000000000000"  # noqa: E501
                        ],
                    },
                ],
                "chainId": "0x76c",
            },
            "0xfad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19",
            HexBytes(
                "0x01f8ad82076c22843b9aca00830186a09409616c3d61b3331fc4109a9e41a8bdb7d9776609865af3107a400086616263646566f838f7940000000000000000000000000000000000000001e1a0010000000000000000000000000000000000000000000000000000000000000001a08289e85fa00f8f7f78a53cf147a87b2a7f0d27e64d7571f9d06a802e365c3430a017dc77eae36c88937db4a5179f57edc6119701652f3f1c6f194d1210d638a061"  # noqa: E501
            ),
            HexBytes(
                "0x2a791d5483705e444fa6d493e6f504836cf54ca78335c60dc81bcf320e95e49c"
            ),
            59044332146903025833144089863119240337233261477961028574753111682592582415408,  # noqa: E501
            10792729512059697976635619515571917958852106732672247829612911298843986403425,  # noqa: E501
            1,
        ),
    ),
    ids=[
        "web3js_hex_str_example",
        "web3js_eth_keys.datatypes.PrivateKey_example",
        "31byte_r_and_s",
        "access_list_tx",
    ],
)
def test_eth_account_sign_transaction(
    acct, txn, private_key, expected_raw_tx, tx_hash, r, s, v
):
    signed = acct.sign_transaction(txn, private_key)
    assert signed.r == signed["r"] == r
    assert signed.s == signed["s"] == s
    assert signed.v == signed["v"] == v
    assert signed.raw_transaction == signed["raw_transaction"] == expected_raw_tx
    assert signed.hash == signed["hash"] == tx_hash

    account = acct.from_key(private_key)
    assert account.sign_transaction(txn) == signed


@pytest.mark.parametrize(
    "transaction",
    ETH_TEST_TRANSACTIONS,
)
def test_eth_account_sign_transaction_from_eth_test(acct, transaction):
    expected_raw_txn = transaction["signed"]
    key = transaction["key"]

    unsigned_txn = dissoc(transaction, "key", "signed", "unsigned")

    # validate r, in order to validate the transaction hash
    # There is some ambiguity about whether `r` will always be deterministically
    # generated from the transaction hash and private key, mostly due to code
    # author's ignorance. The example test fixtures and implementations seem to
    # agree, so far. See ecdsa_raw_sign() in /eth_keys/backends/native/ecdsa.py
    signed = acct.sign_transaction(unsigned_txn, key)
    assert signed.r == to_int(hexstr=expected_raw_txn[-130:-66])

    # confirm that signed transaction can be recovered to the sender
    expected_sender = acct.from_key(key).address
    assert acct.recover_transaction(signed.raw_transaction) == expected_sender


def test_set_key_backend_applies_to_sign_transaction_with_raw_private_key():
    TrackingBackend.reset()
    account_api = Account()
    account_api.set_key_backend(TrackingBackend())
    transaction = dissoc(ETH_TEST_TRANSACTIONS[0], "key", "signed", "unsigned")

    account_api.sign_transaction(transaction, PRIVATE_KEY_AS_BYTES)

    assert TrackingBackend.sign_calls == 1


def test_local_account_sign_transaction_preserves_private_key_backend():
    TrackingBackend.reset()
    account = Account().from_key(
        keys.PrivateKey(PRIVATE_KEY_AS_BYTES, TrackingBackend())
    )
    transaction = dissoc(ETH_TEST_TRANSACTIONS[0], "key", "signed", "unsigned")

    account.sign_transaction(transaction)

    assert TrackingBackend.sign_calls == 1


@pytest.mark.parametrize(
    "transaction",
    ETH_TEST_TRANSACTIONS,
)
def test_eth_account_recover_transaction_from_eth_test(acct, transaction):
    raw_txn = transaction["signed"]
    expected_sender = acct.from_key(transaction["key"]).address
    assert acct.recover_transaction(raw_txn) == expected_sender


def get_encrypt_test_params():
    """
    Params for testing Account#encrypt. Due to not being able to provide fixtures to
    pytest.mark.parametrize, we opt for creating the params in a non-fixture method
    here instead of providing fixtures for the private key and password.
    """
    key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    key_bytes = to_bytes(hexstr=key)
    private_key = keys.PrivateKey(HexBytes(key))
    password = "test!"

    # 'private_key, password, kdf, iterations, expected_decrypted_key, expected_kdf'
    return [
        (key, password, None, None, key_bytes, "scrypt"),
        (private_key, password, None, 2, private_key.to_bytes(), "scrypt"),
        (key, password, "pbkdf2", 4, key_bytes, "pbkdf2"),
        (key, password, None, 8, key_bytes, "scrypt"),
        (key, password, "pbkdf2", 16, key_bytes, "pbkdf2"),
        (key, password, "scrypt", 32, key_bytes, "scrypt"),
    ]


@pytest.mark.parametrize(
    "private_key, password, kdf, iterations, expected_decrypted_key, expected_kdf",
    get_encrypt_test_params(),
    ids=[
        "hex_str",
        "eth_keys.datatypes.PrivateKey",
        "hex_str_provided_kdf",
        "hex_str_default_kdf_provided_iterations",
        "hex_str_pbkdf2_provided_iterations",
        "hex_str_scrypt_provided_iterations",
    ],
)
def test_eth_account_encrypt(
    acct, private_key, password, kdf, iterations, expected_decrypted_key, expected_kdf
):
    if kdf is None:
        encrypted = acct.encrypt(private_key, password, iterations=iterations)
    else:
        encrypted = acct.encrypt(private_key, password, kdf=kdf, iterations=iterations)

    assert encrypted["address"] == "2c7536E3605D9C16a7a3D7b1898e529396a65c23"
    assert encrypted["version"] == 3
    assert encrypted["crypto"]["kdf"] == expected_kdf

    if iterations is None:
        expected_iterations = get_default_work_factor_for_kdf(expected_kdf)
    else:
        expected_iterations = iterations

    if expected_kdf == "pbkdf2":
        assert encrypted["crypto"]["kdfparams"]["c"] == expected_iterations
    elif expected_kdf == "scrypt":
        assert encrypted["crypto"]["kdfparams"]["n"] == expected_iterations
    else:
        raise Exception(
            f"test must be upgraded to confirm iterations with kdf {expected_kdf}"
        )

    decrypted_key = acct.decrypt(encrypted, password)

    assert decrypted_key == expected_decrypted_key


@pytest.mark.parametrize(
    "private_key, password, kdf, iterations, expected_decrypted_key, expected_kdf",
    get_encrypt_test_params(),
    ids=[
        "hex_str",
        "eth_keys.datatypes.PrivateKey",
        "hex_str_provided_kdf",
        "hex_str_default_kdf_provided_iterations",
        "hex_str_pbkdf2_provided_iterations",
        "hex_str_scrypt_provided_iterations",
    ],
)
def test_eth_account_prepared_encrypt(
    acct, private_key, password, kdf, iterations, expected_decrypted_key, expected_kdf
):
    account = acct.from_key(private_key)

    if kdf is None:
        encrypted = account.encrypt(password, iterations=iterations)
    else:
        encrypted = account.encrypt(password, kdf=kdf, iterations=iterations)

    assert encrypted["address"] == "2c7536E3605D9C16a7a3D7b1898e529396a65c23"
    assert encrypted["version"] == 3
    assert encrypted["crypto"]["kdf"] == expected_kdf

    if iterations is None:
        expected_iterations = get_default_work_factor_for_kdf(expected_kdf)
    else:
        expected_iterations = iterations

    if expected_kdf == "pbkdf2":
        assert encrypted["crypto"]["kdfparams"]["c"] == expected_iterations
    elif expected_kdf == "scrypt":
        assert encrypted["crypto"]["kdfparams"]["n"] == expected_iterations
    else:
        raise Exception(
            f"test must be upgraded to confirm iterations with kdf {expected_kdf}"
        )

    decrypted_key = acct.decrypt(encrypted, password)

    assert isinstance(decrypted_key, HexBytes)
    assert decrypted_key == expected_decrypted_key


@pytest.mark.parametrize("test_case", ALL_VALID_EIP712_MESSAGES)
def test_sign_typed_data_produces_same_result_as_encode_plus_sign(acct, test_case):
    test_message = ALL_VALID_EIP712_MESSAGES[test_case]
    encoded = encode_typed_data(full_message=test_message)
    signed_encoded = acct.sign_message(encoded, PRIVATE_KEY_AS_HEXSTR)
    assert (
        acct.sign_typed_data(PRIVATE_KEY_AS_HEXSTR, full_message=test_message)
        == signed_encoded
    )


@pytest.mark.parametrize(
    "domain_data, message_types, message_data, expected_sig",
    (
        (
            {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            },
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "contents", "type": "string"},
                ],
            },
            {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
                },
                "contents": "Hello, Bob!",
            },
            HexBytes(
                "0x33600224dbc5a598b7c443b0cc9241b4b12ea10441244cc058442b31065b37232258c5d0b55f22362b1fa97d5c7fca4f40bfc1545417d974a22dfd4a8ac2de8b1b"  # noqa: E501
            ),
        ),
        (
            {
                "name": "Ether Mail",
                "version": "1",
                "chainId": 1,
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
            },
            {
                "Person": [
                    {"name": "name", "type": "string"},
                    {"name": "wallet", "type": "address"},
                ],
                "Mail": [
                    {"name": "from", "type": "Person"},
                    {"name": "to", "type": "Person"},
                    {"name": "cc", "type": "Person[]"},
                    {"name": "contents", "type": "string"},
                ],
            },
            {
                "from": {
                    "name": "Cow",
                    "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
                },
                "to": {
                    "name": "Bob",
                    "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
                },
                "cc": [
                    {
                        "name": "Alice",
                        "wallet": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    },
                    {
                        "name": "Dot",
                        "wallet": "0xdddddddddddddddddddddddddddddddddddddddd",
                    },
                ],
                "contents": "Hello, Bob!",
            },
            HexBytes(
                "0xfcd28bfd425a26215d645481af446895f761b16896ac007c86433136ad9bb5c815ccdef9a6947396be54e92955c5c707ce65099d0371b4488143264675f5e18b1c"  # noqa: E501
            ),
        ),
    ),
)
def test_sign_typed_data_produces_expected_hash(
    acct, domain_data, message_types, message_data, expected_sig
):
    assert (
        acct.sign_typed_data(
            PRIVATE_KEY_AS_HEXSTR, domain_data, message_types, message_data
        ).signature
        == expected_sig
    )


def test_sign_authorization(acct):
    auth = {
        "chainId": 1,
        "address": "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E",
        "nonce": 0,
    }

    signed_auth = acct.sign_authorization(auth, PRIVATE_KEY_AS_HEXSTR)
    assert signed_auth.chain_id == 1
    assert signed_auth.address == to_bytes(
        hexstr="0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"
    )
    assert signed_auth.nonce == 0
    assert signed_auth.authority == to_bytes(hexstr=ACCT_ADDRESS)

    # assert the authority is the same as the recovered authority, effectively also
    # asserting that the auth hash and signature are correct
    assert acct._recover_hash(
        signed_auth.authorization_hash, vrs=signed_auth.signature.vrs
    ) == to_checksum_address(signed_auth.authority)


def test_sign_authorization_from_local_acct():
    local_acct = Account.from_key(PRIVATE_KEY_AS_HEXSTR)
    auth = {
        "chainId": 1,
        "address": "0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E",
        "nonce": 0,
    }

    signed_auth = local_acct.sign_authorization(auth)
    assert signed_auth.chain_id == 1
    assert signed_auth.address == to_bytes(
        hexstr="0x5ce9454909639D2D17A3F753ce7d93fa0b9aB12E"
    )
    assert signed_auth.nonce == 0

    # assert the authority is the same as the recovered authority, effectively also
    # asserting that the auth hash and signature are correct
    assert Account._recover_hash(
        signed_auth.authorization_hash, vrs=signed_auth.signature.vrs
    ) == to_checksum_address(signed_auth.authority)
