import pytest
import glob
import json
import os

from eth_utils import (
    ValidationError,
    to_bytes,
)
from hexbytes import (
    HexBytes,
)
import rlp
from toolz import (
    merge,
)

from eth_account import (
    Account,
)
from eth_account.typed_transactions import (
    BlobTransaction,
)

TEST_DATA_PATH = os.path.join(os.path.dirname(__file__), "_test_data")
SIGNED_TX_PATH = os.path.join(TEST_DATA_PATH, "signed_tx.txt")
BLOB_DATA_1_PATH = os.path.join(TEST_DATA_PATH, "blob_data_1.txt")
BLOB_DATA_1_SIGNED_PATH = os.path.join(TEST_DATA_PATH, "blob_data_1_signed.txt")
ZERO_BLOB_EIP7594_SIGNED_PATH = os.path.join(
    TEST_DATA_PATH, "zero_blob_eip7594_signed.txt"
)
CONSENSUS_SPEC_TESTS_PATH = os.path.join(
    TEST_DATA_PATH,
    "consensus_spec_tests",
    "fulu",
    "kzg",
    "compute_cells_and_kzg_proofs",
)
GO_ETH_KZG_COMPUTED_PATH = os.path.join(TEST_DATA_PATH, "go_eth_kzg_computed.json")

TEST_ACCT = Account.from_key(
    "0x4646464646464646464646464646464646464646464646464646464646464646"
)

ZERO_BLOB = f"0x{'00' * 32 * 4096}"
ZERO_BLOB_VERSIONED_HASH = (
    "0x010657f37554c781402a22917dee2f75def7ab966d7b770905398eba3c444014"
)
ZERO_BLOB_COMMITMENT_AND_PROOF_HASH = "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"  # noqa: E501
BLOB_TX_DICT = {
    "chainId": 1,
    "nonce": 1,
    "maxPriorityFeePerGas": 50,
    "maxFeePerGas": 1000,
    "gas": 100000,
    "to": "0x45Ae5777c9b35Eb16280e423b0d7c91C06C66B58",
    "value": 1,
    "data": "0x52fdfc072182654f",
    "maxFeePerBlobGas": 100,
}


def test_validation_when_blobs_are_present_with_incorrect_versioned_hashes_in_tx_dict():
    tx_dict_with_wrong_versioned_hashes = merge(
        BLOB_TX_DICT, {"blobVersionedHashes": [f"0x{'00' * 32}"]}
    )
    with pytest.raises(
        ValidationError,
        match=(
            "`blobVersionedHashes` value defined in transaction does not match "
            "versioned hashes computed from blobs."
        ),
    ):
        BlobTransaction.from_dict(
            tx_dict_with_wrong_versioned_hashes,
            blobs=[to_bytes(hexstr=ZERO_BLOB)],
        )


def test_blobs_commitments_proofs_and_hashes_from_blobs():
    # test that when correct blobVersionedHashes value is passed into tx dict,
    # validation does not raise
    correct_versioned_hashes = [ZERO_BLOB_VERSIONED_HASH]
    tx_dict_with_correct_versioned_hashes = merge(
        BLOB_TX_DICT, {"blobVersionedHashes": correct_versioned_hashes}
    )

    # test does not raise
    tx = BlobTransaction.from_dict(
        tx_dict_with_correct_versioned_hashes,
        blobs=[to_bytes(hexstr=ZERO_BLOB)],
    )
    assert (
        len(tx.blob_data.blobs)
        == len(tx.blob_data.versioned_hashes)
        == len(tx.blob_data.proofs)
        == 1
    )
    # assert calculated versioned hash is the same as the provided versioned hash
    assert tx.blob_data.versioned_hashes[0].as_hexstr() == ZERO_BLOB_VERSIONED_HASH

    assert (
        tx.blob_data.commitments[0].as_hexstr() == ZERO_BLOB_COMMITMENT_AND_PROOF_HASH
    )
    assert tx.blob_data.proofs[0].as_hexstr() == ZERO_BLOB_COMMITMENT_AND_PROOF_HASH


def test_sign_blob_transaction_matches_expected_bytes():
    with open(ZERO_BLOB_EIP7594_SIGNED_PATH) as f:
        expected_tx_bytes = to_bytes(hexstr=f.read().strip("\n"))

    signed_tx = TEST_ACCT.sign_transaction(BLOB_TX_DICT, blobs=[ZERO_BLOB])
    assert signed_tx.raw_transaction == HexBytes(expected_tx_bytes)


def test_blob_transaction_calculation_with_nonzero_blob():
    with open(BLOB_DATA_1_PATH) as blob_data_1_file:
        blob_data_1 = to_bytes(hexstr=blob_data_1_file.read().strip("\n"))

    tx = BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[blob_data_1])
    assert len(tx.blob_data.blobs) == len(tx.blob_data.versioned_hashes) == 1
    assert len(tx.blob_data.cell_proofs) == 128

    assert tx.blob_data.blobs[0].as_bytes() == blob_data_1
    assert tx.blob_data.versioned_hashes[0].as_hexstr() == (
        "0x018ef96865998238a5e1783b6cafbc1253235d636f15d318f1fb50ef6a5b8f6a"
    )
    assert tx.blob_data.commitments[0].as_hexstr() == (
        "0xb44bafc7381d7ba2072cfbb7091c1fa1fdabcf3999270a551fe54a6741ddebc1bdfbeeabe1b74f5c3935aeedf6b2db84"  # noqa: E501
    )
    assert tx.blob_data.proofs[0].as_hexstr() == (
        "0x963150f3ee4d5e5f065429f587b4fa199cd8a866b8f6388eb52372870052603c98194c6521077c3260c41bf3b796c833"  # noqa: E501
    )

    # Verify roundtrip works
    signed = TEST_ACCT.sign_transaction(tx.dictionary, blobs=[blob_data_1])
    tx_from_bytes = BlobTransaction.from_bytes(signed.raw_transaction)
    assert tx_from_bytes.blob_data.blobs[0].as_bytes() == blob_data_1
    assert len(tx_from_bytes.blob_data.cell_proofs) == 128


def test_high_and_low_blob_count_limit_validation():
    with pytest.raises(ValidationError, match="must contain at least 1 blob"):
        BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[])

    # make sure up to 6 blobs can be added to a blob transaction
    BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[to_bytes(hexstr=ZERO_BLOB)] * 6)

    # assert raises if more than 6 blobs
    with pytest.raises(ValidationError, match="cannot contain more than 6 blobs"):
        BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[to_bytes(hexstr=ZERO_BLOB)] * 7)


# --- EIP-7594 PeerDAS Cell Proofs Tests ---


def test_deserialize_legacy_eip4844_transaction():
    with open(SIGNED_TX_PATH) as signed_tx_file:
        legacy_tx_bytes = HexBytes(to_bytes(hexstr=signed_tx_file.read().strip("\n")))

    tx = BlobTransaction.from_bytes(legacy_tx_bytes)

    assert tx.blob_data is not None
    assert len(tx.blob_data.blobs) == 1
    assert tx.blob_data.blobs[0].as_hexstr() == ZERO_BLOB

    assert len(tx.blob_data.cell_proofs) == 128

    assert tx.blob_data.versioned_hashes[0].as_hexstr() == ZERO_BLOB_VERSIONED_HASH
    assert (
        tx.blob_data.commitments[0].as_hexstr() == ZERO_BLOB_COMMITMENT_AND_PROOF_HASH
    )


def test_deserialize_legacy_eip4844_transaction_with_nonzero_blob():
    with open(BLOB_DATA_1_PATH) as blob_data_file:
        expected_blob = to_bytes(hexstr=blob_data_file.read().strip("\n"))

    with open(BLOB_DATA_1_SIGNED_PATH) as signed_tx_file:
        legacy_tx_bytes = HexBytes(to_bytes(hexstr=signed_tx_file.read().strip("\n")))

    tx = BlobTransaction.from_bytes(legacy_tx_bytes)

    assert tx.blob_data is not None
    assert len(tx.blob_data.blobs) == 1
    assert tx.blob_data.blobs[0].as_bytes() == expected_blob

    assert len(tx.blob_data.cell_proofs) == 128

    assert tx.blob_data.versioned_hashes[0].as_hexstr() == (
        "0x018ef96865998238a5e1783b6cafbc1253235d636f15d318f1fb50ef6a5b8f6a"
    )
    assert tx.blob_data.commitments[0].as_hexstr() == (
        "0xb44bafc7381d7ba2072cfbb7091c1fa1fdabcf3999270a551fe54a6741ddebc1bdfbeeabe1b74f5c3935aeedf6b2db84"  # noqa: E501
    )


def _get_consensus_spec_test_cases():
    test_cases = []
    pattern = os.path.join(CONSENSUS_SPEC_TESTS_PATH, "*_valid_*", "data.json")
    for test_file in glob.glob(pattern):
        test_name = os.path.basename(os.path.dirname(test_file))
        test_cases.append((test_name, test_file))
    return test_cases


@pytest.mark.parametrize(
    "test_name,test_file",
    _get_consensus_spec_test_cases(),
    ids=lambda x: x if isinstance(x, str) and "valid" in x else "",
)
def test_cell_proofs_match_consensus_spec_vectors(test_name, test_file):
    """
    Test that computed cell proofs match ethereum/consensus-spec-tests vectors
    release: v1.6.0-beta.0
    """
    with open(test_file) as f:
        test_data = json.load(f)

    blob_hex = test_data["input"]["blob"]
    blob_bytes = to_bytes(hexstr=blob_hex)

    test_data["output"][0]
    expected_proofs = test_data["output"][1]

    tx = BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[blob_bytes])

    assert len(tx.blob_data.cell_proofs) == 128

    for _i, (computed_proof, expected_proof) in enumerate(
        zip(tx.blob_data.cell_proofs, expected_proofs, strict=False)
    ):
        assert computed_proof.as_hexstr() == expected_proof.lower()


def test_cell_proofs_count_with_multiple_blobs():
    blob = to_bytes(hexstr=ZERO_BLOB)

    for num_blobs in [1, 2, 3, 6]:
        tx = BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[blob] * num_blobs)
        expected_proofs = 128 * num_blobs
        assert len(tx.blob_data.cell_proofs) == expected_proofs


def test_blob_transaction_roundtrip_with_cell_proofs():
    """Test signing a blob transaction and deserializing it back."""
    blob = to_bytes(hexstr=ZERO_BLOB)
    tx = BlobTransaction.from_dict(BLOB_TX_DICT, blobs=[blob])

    signed_tx = TEST_ACCT.sign_transaction(tx.dictionary, blobs=[blob])

    tx_from_bytes = BlobTransaction.from_bytes(signed_tx.raw_transaction)

    assert tx_from_bytes.blob_data is not None
    assert len(tx_from_bytes.blob_data.blobs) == 1
    assert len(tx_from_bytes.blob_data.versioned_hashes) == 1
    assert len(tx_from_bytes.blob_data.cell_proofs) == 128

    assert tx_from_bytes.blob_data.blobs[0].as_hexstr() == ZERO_BLOB

    assert (
        tx_from_bytes.blob_data.versioned_hashes[0].as_hexbytes()
        == tx_from_bytes.dictionary["blobVersionedHashes"][0]
        == HexBytes(ZERO_BLOB_VERSIONED_HASH)
    )

    assert (
        tx_from_bytes.blob_data.commitments[0].as_hexstr()
        == ZERO_BLOB_COMMITMENT_AND_PROOF_HASH
    )

    for _i, (original, deserialized) in enumerate(
        zip(
            tx.blob_data.cell_proofs,
            tx_from_bytes.blob_data.cell_proofs,
            strict=False,
        )
    ):
        assert original.as_hexstr() == deserialized.as_hexstr()


def _get_go_eth_kzg_test_cases():
    """
    Load test vectors for cross-validating eth-account's blob transaction
    implementation against go-ethereum's.

    Pairs blob inputs from consensus-spec-tests with pre-computed signed
    transactions generated by `go-kzg-verify` (a Go tool using go-eth-kzg).
    Returns tuples of (test_name, blob_hex, expected_signed_tx_hex).
    """
    with open(GO_ETH_KZG_COMPUTED_PATH) as f:
        go_eth_kzg_data = {item["test_name"]: item for item in json.load(f)}

    test_cases = []
    pattern = os.path.join(CONSENSUS_SPEC_TESTS_PATH, "*_valid_*", "data.json")
    for test_file in glob.glob(pattern):
        test_name = os.path.basename(os.path.dirname(test_file))
        if test_name in go_eth_kzg_data:
            with open(test_file) as f:
                json_data = json.load(f)
            test_cases.append(
                (
                    test_name,
                    json_data["input"]["blob"],
                    go_eth_kzg_data[test_name]["signed_transaction_hex"],
                )
            )
    return test_cases


@pytest.mark.parametrize(
    "test_name,blob_hex,expected_tx_hex",
    _get_go_eth_kzg_test_cases(),
    ids=lambda x: x if isinstance(x, str) and "valid" in x else "",
)
def test_signed_tx_bytes_match_go_eth_kzg(test_name, blob_hex, expected_tx_hex):
    blob_bytes = to_bytes(hexstr=blob_hex)
    signed_tx = TEST_ACCT.sign_transaction(BLOB_TX_DICT, blobs=[blob_bytes])
    go_tx_bytes = to_bytes(hexstr=expected_tx_hex)
    assert signed_tx.raw_transaction == HexBytes(go_tx_bytes)


@pytest.mark.parametrize(
    "access_list",
    (
        [],
        [{"address": BLOB_TX_DICT["to"], "storageKeys": []}],
        [
            {"address": BLOB_TX_DICT["to"], "storageKeys": [0, 1, 2**256 - 1]},
            {"address": TEST_ACCT.address, "storageKeys": [1, 1]},
        ],
    ),
    ids=["empty", "address-only", "multiple-addresses-and-keys"],
)
@pytest.mark.parametrize(
    "sidecar_path",
    [None, SIGNED_TX_PATH, ZERO_BLOB_EIP7594_SIGNED_PATH],
    ids=["body-only", "eip4844", "eip7594"],
)
def test_deserialize_blob_transaction_with_access_list(access_list, sidecar_path):
    signed = TEST_ACCT.sign_transaction(
        {
            **BLOB_TX_DICT,
            "accessList": access_list,
            "blobVersionedHashes": [ZERO_BLOB_VERSIONED_HASH],
        }
    )
    body = BlobTransaction.from_bytes(signed.raw_transaction)
    encoded = signed.raw_transaction
    if sidecar_path is not None:
        # Reuse the valid zero-blob sidecar without regenerating its KZG proofs.
        # The access list changes the signed body, not the blob commitment.
        with open(sidecar_path) as sidecar_file:
            wrapper = rlp.decode(HexBytes(sidecar_file.read().strip())[1:])
        wrapper[0] = rlp.decode(signed.raw_transaction[1:])
        encoded = HexBytes(b"\x03" + rlp.encode(wrapper))

    decoded = BlobTransaction.from_bytes(encoded)
    assert decoded.as_dict() == body.as_dict()
    assert decoded.hash() == body.hash()
    assert decoded.vrs() == body.vrs()
    assert Account.recover_transaction(encoded) == TEST_ACCT.address
    if sidecar_path is None:
        assert decoded.blob_data is None
    else:
        assert decoded.blob_data.blobs[0].as_hexstr() == ZERO_BLOB
        assert (
            decoded.blob_data.versioned_hashes[0].as_hexstr()
            == ZERO_BLOB_VERSIONED_HASH
        )


@pytest.mark.parametrize(
    "sidecar_path", [SIGNED_TX_PATH, ZERO_BLOB_EIP7594_SIGNED_PATH]
)
@pytest.mark.parametrize(
    "invalid_access_list",
    [
        [[b"\x11" * 19, []]],
        [[b"\x11" * 20, [b"\x00" * 31]]],
        [[b"\x11" * 20]],
    ],
    ids=["short-address", "short-storage-key", "missing-storage-keys"],
)
def test_deserialize_blob_transaction_rejects_invalid_access_list(
    sidecar_path, invalid_access_list
):
    with open(sidecar_path) as sidecar_file:
        wrapper = rlp.decode(HexBytes(sidecar_file.read().strip())[1:])
    wrapper[0][8] = invalid_access_list
    encoded = HexBytes(b"\x03" + rlp.encode(wrapper))
    with pytest.raises(rlp.exceptions.ObjectDeserializationError):
        BlobTransaction.from_bytes(encoded)
