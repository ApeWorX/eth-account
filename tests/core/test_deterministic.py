import pytest

from eth_utils import (
    ValidationError,
)

from eth_account.hdaccount.deterministic import (
    HardNode,
    HDPath,
    SoftNode,
)


# Test vectors from: https://en.bitcoin.it/wiki/BIP_0032_TestVectors
# Confirmed using https://github.com/richardkiss/pycoin
@pytest.mark.parametrize(
    "seed,path,key",
    [
        # --- BIP32 Testvector 1 ---
        (
            "000102030405060708090a0b0c0d0e0f",
            "m",
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "m/0H",
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "m/0H/1",
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "m/0H/1/2H",
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "m/0H/1/2H/2",
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "m/0H/1/2H/2/1000000000",
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
        ),
        # --- BIP32 Testvector 2 ---
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c"
            "999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m",
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
        ),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c"
            "999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0",
            "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
        ),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c"
            "999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0/2147483647H",
            "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
        ),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c"
            "999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0/2147483647H/1",
            "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
        ),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c"
            "999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0/2147483647H/1/2147483646H",
            "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
        ),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c"
            "999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0/2147483647H/1/2147483646H/2",
            "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
        ),
        # --- BIP32 Testvector 3 ---
        # NOTE: Leading zeros bug https://github.com/iancoleman/bip39/issues/58
        (
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45"
            "d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            "m",
            # NOTE Contains leading zero byte (which was the bug)
            "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
        ),
        (
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45"
            "d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            "m/0H",
            "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
        ),
    ],
)
def test_bip32_testvectors(seed, path, key):
    assert HDPath(path).derive(bytes.fromhex(seed)).hex() == key


def test_reject_index_equal_to_harden_bit():
    with pytest.raises(ValidationError):
        SoftNode(2**31)
    with pytest.raises(ValidationError):
        HardNode(2**31)
    with pytest.raises(ValidationError, match="not valid"):
        HDPath("m/2147483648")
    with pytest.raises(ValidationError, match="not valid"):
        HDPath("m/2147483648'")
    with pytest.raises(ValidationError, match="not valid"):
        HDPath("m/44'/60'/0'/0/2147483648")


def test_accept_max_valid_bip32_index():
    assert int(SoftNode(2**31 - 1)) == 2**31 - 1
    assert int(HardNode(2**31 - 1)) == 2**31 - 1 + 0x80000000
    assert HDPath("m/2147483647").encode() == "m/2147483647"
    assert HDPath("m/2147483647H").encode() == "m/2147483647H"
