from tsl_core import canonicalize, commitment_hash, hash_domain, merkle_root, verify_ed25519


def test_canonicalize_reordered_objects():
    assert canonicalize({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_event_hash_vector():
    payload = {
        "content_commitment": "0x50f62d6063e0d92d02fd4fdafb4b10c38bf271ebb5e14afd037d35b0b35f6b95",
        "disclosure_policy": "commitment_only",
        "event_class": "message",
        "nonce": "0x2222222222222222222222222222222222222222222222222222222222222222",
        "sender": "did:tsl:test:alice",
        "signing_key_id": "#test-key-1",
        "timestamp": "2026-05-25T00:01:00Z",
        "type": "tsl.event_commitment.v1",
    }
    assert hash_domain("tsl.event_commitment.v1", canonicalize(payload).encode("utf-8")) == "0xcf5cb36e4596ed4c446f2d24504407369a1fc4862928e86c340ec5270fcc3267"


def test_commitment_and_merkle_vector():
    event_hash = "0xcf5cb36e4596ed4c446f2d24504407369a1fc4862928e86c340ec5270fcc3267"
    signature = (
        "0xd3187ac9861b87a3b5f871c9ae9a6426ce0c1e49cee1978c767bf99eff6c94467"
        "b6955cd9821c2a7e3bfcf945b576e49d81deccb4e7c8b0624917fd794f1ff08"
    )
    commitment = commitment_hash(event_hash, signature)
    assert commitment == "0x174c377613f1fa94acc95d32408095c27330f5dfa088ee40cdcb81a503b25bb5"
    assert merkle_root([commitment]) == "0xc09632a2beaaf0c4702e673a7a1661673c80be478f1136b60677f38c5bb5914f"


def test_ed25519_vector_verifies_and_tampering_fails():
    public_key = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    event_hash = "0xcf5cb36e4596ed4c446f2d24504407369a1fc4862928e86c340ec5270fcc3267"
    signature = (
        "0xd3187ac9861b87a3b5f871c9ae9a6426ce0c1e49cee1978c767bf99eff6c94467"
        "b6955cd9821c2a7e3bfcf945b576e49d81deccb4e7c8b0624917fd794f1ff08"
    )
    assert verify_ed25519(public_key, event_hash, signature)
    assert not verify_ed25519(public_key, "0x" + "00" * 32, signature)
