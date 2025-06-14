from uecdh.uecdh import UECDH
import time
import uhashlib

if __name__ == "__main__":
    def run_tests():
        """
        Run comprehensive tests for UECDH to ensure reliability.
        """
        print("Running UECDH Test Suite...")
        test_passed = 0
        test_failed = 0

        # Test 1: Basic key exchange (128-bit)
        try:
            alice = UECDH(key_size=16)
            bob = UECDH(key_size=16)
            alice_private, alice_public = alice.generate_keypair()
            bob_private, bob_public = bob.generate_keypair()
            print(f"Alice public key: {alice_public.hex()}")
            print(f"Bob public key: {bob_public.hex()}")
            alice_shared = alice.compute_shared_key(bob_public)
            bob_shared = bob.compute_shared_key(alice_public)
            print(f"Alice shared key: {alice_shared.hex()}")
            print(f"Bob shared key: {bob_shared.hex()}")
            if alice_shared == bob_shared:
                print("Test 1: 128-bit key exchange - PASSED")
                test_passed += 1
            else:
                print("Test 1: 128-bit key exchange - FAILED (Shared keys do not match)")
                test_failed += 1
        except Exception as e:
            print(f"Test 1: 128-bit key exchange - FAILED ({e})")
            test_failed += 1

        # Test 2: 256-bit key exchange
        try:
            alice = UECDH(key_size=32)
            bob = UECDH(key_size=32)
            alice_private, alice_public = alice.generate_keypair()
            bob_private, bob_public = bob.generate_keypair()
            print(f"Alice public key (256-bit): {alice_public.hex()}")
            print(f"Bob public key (256-bit): {bob_public.hex()}")
            alice_shared = alice.compute_shared_key(bob_public)
            bob_shared = bob.compute_shared_key(alice_public)
            print(f"Alice shared key (256-bit): {alice_shared.hex()}")
            print(f"Bob shared key (256-bit): {bob_shared.hex()}")
            if alice_shared == bob_shared:
                print("Test 2: 256-bit key exchange - PASSED")
                test_passed += 1
            else:
                print("Test 2: 256-bit key exchange - FAILED (Shared keys do not match)")
                test_failed += 1
        except Exception as e:
            print(f"Test 2: 256-bit key exchange - FAILED ({e})")
            test_failed += 1

        # Test 3: Weak public key detection
        try:
            alice = UECDH(key_size=16)
            alice_private, alice_public = alice.generate_keypair()
            alice.compute_shared_key(b'\x00' * 16)
            print("Test 3: Weak public key detection - FAILED (Did not catch weak key)")
            test_failed += 1
        except ValueError as e:
            print(f"Test 3: Weak public key detection - PASSED ({e})")
            test_passed += 1
        except Exception as e:
            print(f"Test 3: Weak public key detection - FAILED ({e})")
            test_failed += 1

        # Test 4: Invalid key size
        try:
            invalid = UECDH(key_size=8)
            print("Test 4: Invalid key size detection - FAILED")
            test_failed += 1
        except ValueError:
            print("Test 4: Invalid key size detection - PASSED")
            test_passed += 1
        except Exception as e:
            print(f"Test 4: Invalid key size detection - FAILED ({e})")
            test_failed += 1

        # Test 5: Key cleanup
        try:
            alice = UECDH(key_size=16)
            alice_private, alice_public = alice.generate_keypair()
            alice.clear_keys()
            if alice.private_key is None and alice.public_key is None:
                print("Test 5: Key cleanup - PASSED")
                test_passed += 1
            else:
                print("Test 5: Key cleanup - FAILED")
                test_failed += 1
        except Exception as e:
            print(f"Test 5: Key cleanup - FAILED ({e})")
            test_failed += 1

        # Test 6: Key lifetime expiration
        try:
            alice = UECDH(key_size=16)
            alice_private, alice_public = alice.generate_keypair()
            alice.key_timestamp = time.time() - (alice.MAX_KEY_LIFETIME + 1)
            if not alice.is_key_valid():
                print("Test 6: Key lifetime expiration - PASSED")
                test_passed += 1
            else:
                print("Test 6: Key lifetime expiration - FAILED")
                test_failed += 1
        except Exception as e:
            print(f"Test 6: Key lifetime expiration - FAILED ({e})")
            test_failed += 1

        # Test 7: Custom key pair setting
        try:
            alice = UECDH(key_size=16)
            custom_private = b'\x01' * 16
            custom_public = uhashlib.sha256(custom_private).digest()[:16]
            alice.set_keypair(custom_private, custom_public)
            if alice.private_key == custom_private and alice.public_key == custom_public:
                print("Test 7: Custom key pair setting - PASSED")
                test_passed += 1
            else:
                print("Test 7: Custom key pair setting - FAILED")
                test_failed += 1
        except Exception as e:
            print(f"Test 7: Custom key pair setting - FAILED ({e})")
            test_failed += 1

        # Test 8: Weak custom key detection
        try:
            alice = UECDH(key_size=16)
            alice.set_keypair(b'\x00' * 16, b'\x00' * 16)
            print("Test 8: Weak custom key detection - FAILED")
            test_failed += 1
        except ValueError as e:
            print(f"Test 8: Weak custom key detection - PASSED ({e})")
            test_passed += 1
        except Exception as e:
            print(f"Test 8: Weak custom key detection - FAILED ({e})")
            test_failed += 1

        # Summary
        print(f"\nTest Summary: {test_passed} passed, {test_failed} failed")
        if test_failed == 0:
            print("UECDH is ready for production use on ESP32!")
        else:
            print("Please review failed tests before production use.")

    try:
        run_tests()
    except Exception as e:
        print(f"Test suite failed: {e}")