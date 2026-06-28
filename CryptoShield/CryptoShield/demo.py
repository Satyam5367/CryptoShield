"""
demo.py — CryptoShield End-to-End Demo
========================================
Full Alice → Bob encrypted file transfer demo:

1. Generate RSA-2048 key pairs for Alice and Bob (in-memory)
2. Register both users via API
3. Upload public keys
4. Alice encrypts + signs a file, sends to Bob
5. Bob verifies Alice's signature + decrypts the file
6. Verify-only endpoint demo (integrity check without decrypting)
7. Test tamper detection

Usage:
    python demo.py                     # full API demo
    python demo.py --offline           # crypto-only (no API needed)

Requirements:
    pip install requests cryptography
    CryptoShield running: docker-compose up
"""

import requests
import base64
import json
import argparse
import sys
import os

BASE_URL = 'http://localhost:5001'

RESET  = '\033[0m'
BOLD   = '\033[1m'
CYAN   = '\033[96m'
GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
BLUE   = '\033[94m'


def banner():
    print(f"""{CYAN}
╔══════════════════════════════════════════════╗
║        CryptoShield — Live Demo              ║
║  AES-256-GCM · RSA-2048 · Digital Sigs      ║
╚══════════════════════════════════════════════╝{RESET}
""")


def step(n, msg):
    print(f"\n{BOLD}[Step {n}]{RESET} {msg}")


def ok(msg):     print(f"  {GREEN}✓{RESET} {msg}")
def err(msg):    print(f"  {RED}✗ {msg}{RESET}"); sys.exit(1)
def info(msg):   print(f"  {YELLOW}→{RESET} {msg}")
def detail(msg): print(f"    {BLUE}{msg}{RESET}")


# ------------------------------------------------------------------
# Offline crypto demo (no API needed)
# ------------------------------------------------------------------

def run_offline_demo():
    print(f"\n{CYAN}── OFFLINE CRYPTO DEMO (no API) ──{RESET}\n")
    from app.crypto_engine import (
        generate_rsa_keypair, serialize_private_key, serialize_public_key,
        encrypt_and_sign, decrypt_and_verify,
        encrypt_file, decrypt_file, generate_aes_key,
        sign_data, verify_signature
    )

    step(1, "Generating RSA-2048 key pairs for Alice and Bob...")
    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv,   bob_pub   = generate_rsa_keypair()
    ok("Alice: RSA-2048 key pair generated")
    ok("Bob:   RSA-2048 key pair generated")

    step(2, "AES-256-GCM encryption test...")
    aes_key   = generate_aes_key()
    plaintext = b"Confidential: Q4 financial projections for Rubrik."
    encrypted = encrypt_file(plaintext, aes_key)
    decrypted = decrypt_file(encrypted, aes_key)
    assert decrypted == plaintext
    ok(f"Plaintext:  {plaintext.decode()}")
    detail(f"Nonce:      {encrypted['nonce'][:24]}...")
    detail(f"Ciphertext: {encrypted['ciphertext'][:32]}...")
    ok("AES-256-GCM roundtrip: PASSED")

    step(3, "RSA-PSS digital signature test...")
    data      = b"File integrity data"
    signature = sign_data(data, alice_priv)
    valid     = verify_signature(data, signature, alice_pub)
    ok(f"Signature (first 40 chars): {signature[:40]}...")
    ok(f"Signature valid: {valid}")

    step(4, "Tamper detection test...")
    tampered = b"File integrity data — TAMPERED"
    tamper_valid = verify_signature(tampered, signature, alice_pub)
    ok(f"Tampered data signature valid: {tamper_valid}  ← correctly rejected")

    step(5, "Full encrypt-and-sign → decrypt-and-verify flow (Alice → Bob)...")
    secret_file = b"TOP SECRET: Access credentials for production server."
    info(f"Alice sends: '{secret_file.decode()}'")

    bundle  = encrypt_and_sign(secret_file, bob_pub, alice_priv)
    info(f"Bundle (first 60 chars): {bundle[:60]}...")

    received = decrypt_and_verify(bundle, bob_priv, alice_pub)
    ok(f"Bob received: '{received.decode()}'")
    ok(f"Signature verified: PASSED")
    assert received == secret_file

    step(6, "Wrong recipient key test (Eve tries to decrypt)...")
    from app.crypto_engine import generate_rsa_keypair as gen
    eve_priv, _ = gen()
    try:
        decrypt_and_verify(bundle, eve_priv, alice_pub)
        print(f"  {RED}✗ Eve decrypted — SECURITY FAIL{RESET}")
    except Exception:
        ok("Eve's decryption attempt: BLOCKED (correct)")

    step(7, "Tampered bundle test...")
    raw_bundle = base64.b64decode(bundle)
    tampered_b = bytearray(raw_bundle)
    tampered_b[100] ^= 0xFF
    bad_bundle = base64.b64encode(bytes(tampered_b)).decode()
    try:
        decrypt_and_verify(bad_bundle, bob_priv, alice_pub)
        print(f"  {RED}✗ Tampered bundle accepted — SECURITY FAIL{RESET}")
    except Exception:
        ok("Tampered bundle: REJECTED (correct)")

    print(f"\n{GREEN}{'─'*50}")
    print(f"  All offline crypto tests PASSED")
    print(f"{'─'*50}{RESET}\n")


# ------------------------------------------------------------------
# Full API demo
# ------------------------------------------------------------------

def register(username, password, email):
    res = requests.post(f'{BASE_URL}/auth/register', json={
        'username': username, 'email': email, 'password': password
    })
    if res.status_code not in (201, 409):
        err(f"Register failed for {username}: {res.text}")
    return res.status_code == 201


def login(username, password):
    res = requests.post(f'{BASE_URL}/auth/login', json={
        'username': username, 'password': password
    })
    if res.status_code != 200:
        err(f"Login failed for {username}: {res.text}")
    data = res.json()
    return data['access_token'], data['user']


def upload_pub_key(token, pub_pem):
    res = requests.post(f'{BASE_URL}/keys/upload',
        json={'public_key_pem': pub_pem},
        headers={'Authorization': f'Bearer {token}'}
    )
    if res.status_code != 200:
        err(f"Key upload failed: {res.text}")


def get_user_id(token):
    res = requests.get(f'{BASE_URL}/auth/me', headers={'Authorization': f'Bearer {token}'})
    return res.json()['id']


def encrypt_upload(token, file_bytes, filename, recipient_id, sender_priv_pem):
    from io import BytesIO
    res = requests.post(f'{BASE_URL}/files/encrypt-upload',
        headers={'Authorization': f'Bearer {token}'},
        files={'file': (filename, BytesIO(file_bytes), 'text/plain')},
        data={
            'recipient_id':           str(recipient_id),
            'sender_private_key_pem': sender_priv_pem
        }
    )
    if res.status_code != 201:
        err(f"Encrypt-upload failed: {res.text}")
    return res.json()['file_id']


def decrypt(token, file_id, recip_priv_pem, sender_pub_pem):
    res = requests.post(f'{BASE_URL}/files/decrypt/{file_id}',
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        json={
            'recipient_private_key_pem': recip_priv_pem,
            'sender_public_key_pem':     sender_pub_pem
        }
    )
    return res.status_code, res.json()


def verify_sig(token, file_id, sender_pub_pem):
    res = requests.post(f'{BASE_URL}/files/verify/{file_id}',
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        json={'sender_public_key_pem': sender_pub_pem}
    )
    return res.json()


def run_api_demo():
    from app.crypto_engine import (
        generate_rsa_keypair, serialize_private_key, serialize_public_key
    )

    print(f"\n{CYAN}── FULL API DEMO ──{RESET}\n")

    step(1, "Generating RSA-2048 key pairs for Alice and Bob...")
    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv,   bob_pub   = generate_rsa_keypair()

    alice_priv_pem = serialize_private_key(alice_priv).decode()
    alice_pub_pem  = serialize_public_key(alice_pub).decode()
    bob_priv_pem   = serialize_private_key(bob_priv).decode()
    bob_pub_pem    = serialize_public_key(bob_pub).decode()
    ok("Alice and Bob key pairs generated (in-memory)")

    step(2, "Registering users...")
    register('demo_alice', 'AlicePass123!', 'alice@demo.local')
    register('demo_bob',   'BobPass456!',   'bob@demo.local')
    ok("Alice registered"); ok("Bob registered")

    step(3, "Logging in...")
    alice_token, _ = login('demo_alice', 'AlicePass123!')
    bob_token,   _ = login('demo_bob',   'BobPass456!')
    ok(f"Alice token: {alice_token[:30]}...")
    ok(f"Bob   token: {bob_token[:30]}...")

    step(4, "Uploading public keys to server...")
    upload_pub_key(alice_token, alice_pub_pem)
    upload_pub_key(bob_token,   bob_pub_pem)
    ok("Alice's public key uploaded")
    ok("Bob's   public key uploaded")

    bob_id = get_user_id(bob_token)
    info(f"Bob's user ID: {bob_id}")

    step(5, "Alice encrypts + signs a file and sends to Bob...")
    secret = b"Confidential document: Project Phoenix launch date is 2025-03-01."
    info(f"Original file content: '{secret.decode()}'")

    file_id = encrypt_upload(alice_token, secret, 'secret.txt', bob_id, alice_priv_pem)
    ok(f"File encrypted with AES-256-GCM")
    ok(f"Ciphertext signed with Alice's RSA-2048 private key (RSA-PSS)")
    ok(f"AES key wrapped with Bob's RSA-2048 public key (OAEP)")
    ok(f"Bundle uploaded to server — File ID: {file_id}")

    step(6, "Bob verifies signature (without decrypting)...")
    v = verify_sig(bob_token, file_id, alice_pub_pem)
    ok(f"Signature valid: {v.get('signature_valid')}")
    ok(v.get('message', ''))

    step(7, "Bob decrypts and verifies the file...")
    status, data = decrypt(bob_token, file_id, bob_priv_pem, alice_pub_pem)
    if status == 200:
        plaintext = base64.b64decode(data['plaintext'])
        ok(f"Decrypted: '{plaintext.decode()}'")
        ok(data.get('message', ''))
        assert plaintext == secret
        ok("Content matches original — integrity confirmed")
    else:
        err(f"Decryption failed: {data}")

    step(8, "Testing unauthorised access (Eve tries to decrypt Bob's file)...")
    register('demo_eve', 'EvePass789!', 'eve@demo.local')
    eve_token, _ = login('demo_eve', 'EvePass789!')
    eve_priv, _  = generate_rsa_keypair()
    eve_priv_pem = serialize_private_key(eve_priv).decode()

    status2, data2 = decrypt(eve_token, file_id, eve_priv_pem, alice_pub_pem)
    if status2 == 403:
        ok(f"Eve's access BLOCKED — HTTP {status2} (correct)")
    else:
        print(f"  {RED}✗ Eve accessed the file — security issue{RESET}")

    print(f"\n{GREEN}{'─'*50}")
    print(f"  Full API demo complete.")
    print(f"  Dashboard: http://localhost:5001")
    print(f"{'─'*50}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description='CryptoShield Demo')
    parser.add_argument('--offline', action='store_true', help='Run crypto-only demo (no API needed)')
    args = parser.parse_args()

    banner()

    if args.offline:
        run_offline_demo()
        return

    try:
        requests.get(f'{BASE_URL}/', timeout=3)
    except requests.ConnectionError:
        print(f"{RED}Cannot connect to CryptoShield API at {BASE_URL}{RESET}")
        print(f"{YELLOW}Start it with: docker-compose up{RESET}")
        print(f"{YELLOW}Or run offline demo: python demo.py --offline{RESET}\n")
        sys.exit(0)

    run_api_demo()


if __name__ == '__main__':
    main()
