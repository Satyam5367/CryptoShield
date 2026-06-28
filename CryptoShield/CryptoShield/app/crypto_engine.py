"""
CryptoShield Crypto Engine
- AES-256-GCM for symmetric file encryption (authenticated encryption)
- RSA-2048 for secure key exchange
- Digital signatures (RSA-PSS) for file integrity and non-repudiation
"""

import os
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1, PSS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ------------------------------------------------------------------
# RSA Key Generation
# ------------------------------------------------------------------

def generate_rsa_keypair():
    """Generate an RSA-2048 key pair. Returns (private_key, public_key) objects."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def serialize_private_key(private_key, password: bytes = None) -> bytes:
    """Serialize private key to PEM. Optionally encrypt with password."""
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )


def serialize_public_key(public_key) -> bytes:
    """Serialize public key to PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key(pem_data: bytes, password: bytes = None):
    """Load private key from PEM bytes."""
    return serialization.load_pem_private_key(pem_data, password=password, backend=default_backend())


def load_public_key(pem_data: bytes):
    """Load public key from PEM bytes."""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


# ------------------------------------------------------------------
# AES-256-GCM Encryption / Decryption
# ------------------------------------------------------------------

def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(32)


def encrypt_file(plaintext: bytes, aes_key: bytes) -> dict:
    """
    Encrypt bytes using AES-256-GCM (authenticated encryption).

    Returns a dict with:
        nonce       - 12-byte random nonce (base64)
        ciphertext  - encrypted data (base64)
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return {
        'nonce':      base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }


def decrypt_file(encrypted: dict, aes_key: bytes) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext. Raises ValueError if authentication tag fails.
    """
    nonce      = base64.b64decode(encrypted['nonce'])
    ciphertext = base64.b64decode(encrypted['ciphertext'])
    aesgcm     = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ------------------------------------------------------------------
# RSA Key Wrapping (Encrypt / Decrypt AES key with RSA)
# ------------------------------------------------------------------

def rsa_encrypt_key(aes_key: bytes, recipient_public_key) -> str:
    """
    Encrypt an AES key using RSA-OAEP with SHA-256.
    Returns base64-encoded encrypted key.
    """
    encrypted = recipient_public_key.encrypt(
        aes_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()


def rsa_decrypt_key(encrypted_key_b64: str, recipient_private_key) -> bytes:
    """
    Decrypt an RSA-OAEP encrypted AES key.
    Returns raw AES key bytes.
    """
    encrypted = base64.b64decode(encrypted_key_b64)
    return recipient_private_key.decrypt(
        encrypted,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ------------------------------------------------------------------
# Digital Signatures (RSA-PSS with SHA-256)
# ------------------------------------------------------------------

def sign_data(data: bytes, private_key) -> str:
    """
    Sign data using RSA-PSS with SHA-256.
    Returns base64-encoded signature.
    """
    signature = private_key.sign(
        data,
        PSS(
            mgf=MGF1(hashes.SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(data: bytes, signature_b64: str, public_key) -> bool:
    """
    Verify RSA-PSS signature.
    Returns True if valid, False if tampered or invalid.
    """
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data,
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------------------
# High-Level Package: Encrypt + Sign + Wrap
# ------------------------------------------------------------------

def encrypt_and_sign(plaintext: bytes, recipient_public_key, sender_private_key) -> str:
    """
    Full encryption pipeline:
    1. Generate ephemeral AES-256 key
    2. Encrypt plaintext with AES-256-GCM
    3. Sign the ciphertext with sender's RSA private key
    4. Encrypt AES key with recipient's RSA public key (OAEP)
    5. Bundle everything into a JSON package (base64-encoded)

    Returns: base64-encoded JSON bundle string
    """
    aes_key       = generate_aes_key()
    encrypted     = encrypt_file(plaintext, aes_key)
    ciphertext_b  = base64.b64decode(encrypted['ciphertext'])
    signature     = sign_data(ciphertext_b, sender_private_key)
    wrapped_key   = rsa_encrypt_key(aes_key, recipient_public_key)

    bundle = {
        'version':       '1.0',
        'algorithm':     'AES-256-GCM + RSA-2048-OAEP + RSA-PSS',
        'nonce':         encrypted['nonce'],
        'ciphertext':    encrypted['ciphertext'],
        'wrapped_key':   wrapped_key,
        'signature':     signature
    }

    return base64.b64encode(json.dumps(bundle).encode()).decode()


def decrypt_and_verify(bundle_b64: str, recipient_private_key, sender_public_key) -> bytes:
    """
    Full decryption pipeline:
    1. Decode the JSON bundle
    2. Unwrap (decrypt) the AES key using recipient's RSA private key
    3. Verify the ciphertext signature using sender's RSA public key
    4. Decrypt ciphertext with AES-256-GCM

    Raises:
        ValueError: if signature verification fails (tampered data)
        Exception:  if decryption fails (wrong key or corrupted data)
    """
    bundle       = json.loads(base64.b64decode(bundle_b64).decode())
    aes_key      = rsa_decrypt_key(bundle['wrapped_key'], recipient_private_key)
    ciphertext_b = base64.b64decode(bundle['ciphertext'])

    if not verify_signature(ciphertext_b, bundle['signature'], sender_public_key):
        raise ValueError('Signature verification failed — file may have been tampered with.')

    return decrypt_file({'nonce': bundle['nonce'], 'ciphertext': bundle['ciphertext']}, aes_key)
