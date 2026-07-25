"""
Test suite for UECDH-X25519 against official RFC 7748 test vectors.
Compatible with both CPython and MicroPython (with minor import changes).
"""

import sys
import binascii

# ---------- Adapt for CPython / MicroPython ----------
try:
    # MicroPython
    from uecdh import UECDH
    import uhashlib as hashlib
except ImportError:
    # CPython fallback – paste the whole UECDH class here or import it
    # For convenience we assume the class is available as UECDH
    from uecdh import UECDH   # change if needed

# ============================================================
# Official RFC 7748 Test Vectors
# ============================================================

# --- Section 5.2 : Variable-base X25519 ---
VECTORS_5_2 = [
    {
        "name": "RFC 7748 §5.2 vector 1",
        "scalar":  "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "u":       "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "output":  "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    },
    {
        "name": "RFC 7748 §5.2 vector 2",
        "scalar":  "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "u":       "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "output":  "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    },
]

# --- Section 6.1 : Diffie-Hellman (Alice / Bob) ---
ALICE_PRIV = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
ALICE_PUB  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
BOB_PRIV   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
BOB_PUB    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
SHARED     = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

# --- Base point ---
BASE_POINT = "0900000000000000000000000000000000000000000000000000000000000000"

# --- Iteration test (after 1 iteration) ---
ITER_1 = "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"


def h2b(hexstr: str) -> bytes:
    return binascii.unhexlify(hexstr)


def b2h(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def test_x25519_core():
    print("=" * 60)
    print("Testing X25519 core function (RFC 7748 §5.2)")
    print("=" * 60)

    passed = 0
    for v in VECTORS_5_2:
        scalar = h2b(v["scalar"])
        u      = h2b(v["u"])
        expected = h2b(v["output"])

        result = UECDH.x25519(scalar, u)

        if result == expected:
            print(f"[PASS] {v['name']}")
            passed += 1
        else:
            print(f"[FAIL] {v['name']}")
            print(f"  Expected: {v['output']}")
            print(f"  Got     : {b2h(result)}")

    # Base point multiplication (Alice)
    alice_pub = UECDH.x25519(h2b(ALICE_PRIV), h2b(BASE_POINT))
    if alice_pub == h2b(ALICE_PUB):
        print("[PASS] Alice public key generation")
        passed += 1
    else:
        print("[FAIL] Alice public key generation")
        print(f"  Expected: {ALICE_PUB}")
        print(f"  Got     : {b2h(alice_pub)}")

    # Base point multiplication (Bob)
    bob_pub = UECDH.x25519(h2b(BOB_PRIV), h2b(BASE_POINT))
    if bob_pub == h2b(BOB_PUB):
        print("[PASS] Bob public key generation")
        passed += 1
    else:
        print("[FAIL] Bob public key generation")
        print(f"  Expected: {BOB_PUB}")
        print(f"  Got     : {b2h(bob_pub)}")

    print(f"\nCore tests passed: {passed}/{len(VECTORS_5_2)+2}")
    return passed == len(VECTORS_5_2) + 2


def test_diffie_hellman():
    print("\n" + "=" * 60)
    print("Testing Diffie-Hellman (RFC 7748 §6.1)")
    print("=" * 60)

    # Alice computes shared secret with Bob's public key
    shared_alice = UECDH.x25519(h2b(ALICE_PRIV), h2b(BOB_PUB))
    # Bob computes shared secret with Alice's public key
    shared_bob   = UECDH.x25519(h2b(BOB_PRIV), h2b(ALICE_PUB))

    expected = h2b(SHARED)

    ok = True
    if shared_alice == expected:
        print("[PASS] Alice's shared secret")
    else:
        print("[FAIL] Alice's shared secret")
        print(f"  Expected: {SHARED}")
        print(f"  Got     : {b2h(shared_alice)}")
        ok = False

    if shared_bob == expected:
        print("[PASS] Bob's shared secret")
    else:
        print("[FAIL] Bob's shared secret")
        print(f"  Expected: {SHARED}")
        print(f"  Got     : {b2h(shared_bob)}")
        ok = False

    if shared_alice == shared_bob:
        print("[PASS] Commutativity (Alice == Bob)")
    else:
        print("[FAIL] Commutativity")
        ok = False

    return ok


def test_iteration():
    print("\n" + "=" * 60)
    print("Testing iteration vector (RFC 7748 §5.2)")
    print("=" * 60)

    k = h2b(BASE_POINT)
    u = h2b(BASE_POINT)

    # One iteration
    k = UECDH.x25519(k, u)
    if k == h2b(ITER_1):
        print("[PASS] After 1 iteration")
        return True
    else:
        print("[FAIL] After 1 iteration")
        print(f"  Expected: {ITER_1}")
        print(f"  Got     : {b2h(k)}")
        return False


def test_high_level_api():
    print("\n" + "=" * 60)
    print("Testing high-level UECDH API (keypair + shared key)")
    print("=" * 60)

    # Simulate Alice
    alice = UECDH()
    alice_priv, alice_pub = alice.generate_keypair()
    # Force known private key for deterministic test
    alice._priv = h2b(ALICE_PRIV)
    alice._pub  = UECDH.x25519(alice._priv, UECDH.BASE_POINT)

    # Simulate Bob
    bob = UECDH()
    bob._priv = h2b(BOB_PRIV)
    bob._pub  = UECDH.x25519(bob._priv, UECDH.BASE_POINT)

    # Exchange public keys
    alice.set_peer_public_key(bob._pub)
    bob.set_peer_public_key(alice._pub)

    # Compute shared keys (without salt for exact match with RFC)
    try:
        key_alice = alice.compute_shared_key(salt=b"", info=b"", length=32)
        key_bob   = bob.compute_shared_key(salt=b"", info=b"", length=32)
    except Exception as e:
        print(f"[FAIL] Exception during compute_shared_key: {e}")
        return False

    # Note: compute_shared_key applies HKDF, so result != raw shared secret.
    # We only check that both sides get the same derived key.
    if key_alice == key_bob:
        print("[PASS] High-level API – both sides derive identical key")
        print(f"       Derived key: {b2h(key_alice)}")
        return True
    else:
        print("[FAIL] High-level API – keys differ")
        print(f"  Alice: {b2h(key_alice)}")
        print(f"  Bob  : {b2h(key_bob)}")
        return False


def main():
    print("UECDH-X25519 RFC 7748 Compliance Test")
    print("Author test suite – July 2026\n")

    results = []
    results.append(("Core X25519",          test_x25519_core()))
    results.append(("Diffie-Hellman §6.1",  test_diffie_hellman()))
    results.append(("Iteration vector",     test_iteration()))
    results.append(("High-level API",       test_high_level_api()))

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    all_ok = True
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  {status:4}  {name}")
        if not ok:
            all_ok = False

    if all_ok:
        print("\n✅  All tests passed – implementation is RFC 7748 compliant.")
        return 0
    else:
        print("\n❌  Some tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())