import pytest

from eth_abi.exceptions import (
    ABITypeError,
)
from eth_utils.toolz import (
    assoc,
    dissoc,
)

from eth_account import (
    Account,
)

GOOD_TXN = {
    "gasPrice": 2,
    "gas": 200000,
    "nonce": 3,
}

TEST_PRIVATE_KEY = b"\0" * 31 + b"\x01"


@pytest.mark.parametrize(
    "txn_dict, bad_fields",
    (
        (dict(GOOD_TXN), {}),
        (dict(GOOD_TXN, to=None), {}),
        (dict(GOOD_TXN, to=b""), {}),
        (dict(GOOD_TXN, to="0x" + "00" * 20), {}),
        (dict(GOOD_TXN, to="0x0d8ce2a99bb6e3b7db580ed848240e4a0f9ae153"), {}),
        (dict(GOOD_TXN, to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"), {}),
        (dict(GOOD_TXN, to="0xf0109Fc8df283027B6285CC889f5Aa624eAc1f55"), {"to"}),
        (dict(GOOD_TXN, to="0x" + "00" * 19), {"to"}),
        (dict(GOOD_TXN, to="0x" + "00" * 21), {"to"}),
        (dict(GOOD_TXN, to=b"\0" * 20), {}),
        (dict(GOOD_TXN, to=b"\0" * 21), {"to"}),
        # from with the right address is allowed
        (assoc(GOOD_TXN, "from", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"), {}),
        # from with a non-checksum address is not
        (
            assoc(GOOD_TXN, "from", "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"),
            {"from"},
        ),
        # from with the wrong address is not
        (
            assoc(GOOD_TXN, "from", "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"),
            {"from"},
        ),
        (dict(GOOD_TXN, gas="0e1"), {"gas"}),
        (dict(GOOD_TXN, gasPrice="0e1"), {"gasPrice"}),
        (dict(GOOD_TXN, value="0e1"), {"value"}),
        (dict(GOOD_TXN, nonce="0e1"), {"nonce"}),
        (dict(GOOD_TXN, gas="0b1"), {"gas"}),
        (dict(GOOD_TXN, gasPrice="0b1"), {"gasPrice"}),
        (dict(GOOD_TXN, value="0b1"), {"value"}),
        (dict(GOOD_TXN, nonce="0b1"), {"nonce"}),
        (dict(GOOD_TXN, chainId=None), {}),
        (dict(GOOD_TXN, chainId="0x1"), {}),
        (dict(GOOD_TXN, chainId="1"), {"chainId"}),
        # superfluous keys will be rejected (note the lower case p)
        (dict(GOOD_TXN, gasprice=1), {"gasprice"}),
        # missing keys will be called out explicitly
        (dissoc(GOOD_TXN, "gasPrice"), {"gasPrice"}),
        (dissoc(GOOD_TXN, "gas"), {"gas"}),
        (dissoc(GOOD_TXN, "nonce"), {"nonce"}),
    ),
)
def test_invalid_transaction_fields(txn_dict, bad_fields):
    if not bad_fields:
        Account.sign_transaction(txn_dict, TEST_PRIVATE_KEY)
    else:
        with pytest.raises((TypeError, ABITypeError)) as excinfo:
            Account.sign_transaction(txn_dict, TEST_PRIVATE_KEY)
        for field in bad_fields:
            assert field in str(excinfo.value)
