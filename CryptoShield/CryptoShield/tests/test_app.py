import pytest
import json
import base64
import io
from app import create_app, db
from app.crypto_engine import (
    generate_rsa_keypair, serialize_private_key, serialize_public_key,
    encrypt_and_sign, decrypt_and_verify,
    encrypt_file, decrypt_file, generate_aes_key,
    sign_data, verify_signature
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['JWT_SECRET_KEY'] = 'test-secret'

    with app.test_client() as c:
        with app.app_context():
            db.create_all()
        yield c


@pytest.fixture
def keypair_alice():
    priv, pub = generate_rsa_keypair()
    return priv, pub


@pytest.fixture
def keypair_bob():
    priv, pub = generate_rsa_keypair()
    return priv, pub


def register_login(client, username, password='SecurePass123!'):
    client.post('/auth/register', json={
        'username': username, 'email': f'{username}@test.com', 'password': password
    })
    res = client.post('/auth/login', json={'username': username, 'password': password})
    return json.loads(res.data)['access_token']


# ------------------------------------------------------------------
# Crypto engine unit tests
# ------------------------------------------------------------------

def test_aes_encrypt_decrypt_roundtrip():
    key       = generate_aes_key()
    plaintext = b'Hello, CryptoShield!'
    encrypted = encrypt_file(plaintext, key)
    decrypted = decrypt_file(encrypted, key)
    assert decrypted == plaintext


def test_aes_wrong_key_fails():
    key       = generate_aes_key()
    wrong_key = generate_aes_key()
    plaintext = b'Secret data'
    encrypted = encrypt_file(plaintext, key)
    with pytest.raises(Exception):
        decrypt_file(encrypted, wrong_key)


def test_rsa_sign_verify():
    priv, pub = generate_rsa_keypair()
    data      = b'Important document'
    sig       = sign_data(data, priv)
    assert verify_signature(data, sig, pub) is True


def test_rsa_verify_tampered_data():
    priv, pub  = generate_rsa_keypair()
    data       = b'Important document'
    sig        = sign_data(data, priv)
    tampered   = b'Tampered document'
    assert verify_signature(tampered, sig, pub) is False


def test_full_encrypt_decrypt_sign_verify(keypair_alice, keypair_bob):
    alice_priv, alice_pub = keypair_alice
    bob_priv,   bob_pub   = keypair_bob

    plaintext = b'Top secret file contents from Alice to Bob.'

    # Alice encrypts + signs for Bob
    bundle = encrypt_and_sign(plaintext, bob_pub, alice_priv)

    # Bob decrypts + verifies Alice's signature
    decrypted = decrypt_and_verify(bundle, bob_priv, alice_pub)

    assert decrypted == plaintext


def test_tampered_bundle_raises(keypair_alice, keypair_bob):
    alice_priv, alice_pub = keypair_alice
    bob_priv,   bob_pub   = keypair_bob

    bundle = encrypt_and_sign(b'Original content', bob_pub, alice_priv)

    # Tamper: flip a byte in the bundle
    raw    = base64.b64decode(bundle)
    tamper = bytearray(raw)
    tamper[50] ^= 0xFF
    bad_bundle = base64.b64encode(bytes(tamper)).decode()

    with pytest.raises(Exception):
        decrypt_and_verify(bad_bundle, bob_priv, alice_pub)


def test_wrong_recipient_key_fails(keypair_alice, keypair_bob):
    alice_priv, alice_pub = keypair_alice
    bob_priv,   bob_pub   = keypair_bob
    eve_priv,   eve_pub   = generate_rsa_keypair()

    bundle = encrypt_and_sign(b'Only for Bob', bob_pub, alice_priv)

    # Eve tries to decrypt with her key
    with pytest.raises(Exception):
        decrypt_and_verify(bundle, eve_priv, alice_pub)


# ------------------------------------------------------------------
# API tests
# ------------------------------------------------------------------

def test_register_success(client):
    res = client.post('/auth/register', json={
        'username': 'testuser', 'email': 'test@test.com', 'password': 'Password123!'
    })
    assert res.status_code == 201


def test_login_success(client):
    client.post('/auth/register', json={
        'username': 'logintest', 'email': 'l@test.com', 'password': 'Password123!'
    })
    res = client.post('/auth/login', json={'username': 'logintest', 'password': 'Password123!'})
    assert res.status_code == 200
    assert 'access_token' in json.loads(res.data)


def test_login_wrong_password(client):
    client.post('/auth/register', json={
        'username': 'wrongpass', 'email': 'wp@test.com', 'password': 'Password123!'
    })
    res = client.post('/auth/login', json={'username': 'wrongpass', 'password': 'wrong'})
    assert res.status_code == 401


def test_upload_public_key(client, keypair_alice):
    _, alice_pub = keypair_alice
    token = register_login(client, 'alice')
    pub_pem = serialize_public_key(alice_pub).decode()

    res = client.post('/keys/upload',
                      json={'public_key_pem': pub_pem},
                      headers={'Authorization': f'Bearer {token}'})
    assert res.status_code == 200


def test_encrypt_upload_and_decrypt(client, keypair_alice, keypair_bob):
    alice_priv, alice_pub = keypair_alice
    bob_priv,   bob_pub   = keypair_bob

    alice_token = register_login(client, 'alice2')
    bob_token   = register_login(client, 'bob2')

    # Bob uploads his public key
    bob_pub_pem = serialize_public_key(bob_pub).decode()
    client.post('/keys/upload',
                json={'public_key_pem': bob_pub_pem},
                headers={'Authorization': f'Bearer {bob_token}'})

    # Get Bob's user id
    me_res = client.get('/auth/me', headers={'Authorization': f'Bearer {bob_token}'})
    bob_id = json.loads(me_res.data)['id']

    # Alice encrypts and uploads to Bob
    alice_priv_pem = serialize_private_key(alice_priv).decode()
    file_data = b'Super secret file content'

    res = client.post('/files/encrypt-upload',
                      data={
                          'recipient_id':         str(bob_id),
                          'sender_private_key_pem': alice_priv_pem,
                          'file': (io.BytesIO(file_data), 'secret.txt')
                      },
                      content_type='multipart/form-data',
                      headers={'Authorization': f'Bearer {alice_token}'})
    assert res.status_code == 201
    file_id = json.loads(res.data)['file_id']

    # Bob decrypts
    alice_pub_pem = serialize_public_key(alice_pub).decode()
    bob_priv_pem  = serialize_private_key(bob_priv).decode()

    dec_res = client.post(f'/files/decrypt/{file_id}',
                          json={
                              'recipient_private_key_pem': bob_priv_pem,
                              'sender_public_key_pem':     alice_pub_pem
                          },
                          headers={'Authorization': f'Bearer {bob_token}'})
    assert dec_res.status_code == 200
    result = json.loads(dec_res.data)
    assert base64.b64decode(result['plaintext']) == file_data


def test_non_recipient_cannot_decrypt(client, keypair_alice, keypair_bob):
    alice_priv, alice_pub = keypair_alice
    bob_priv,   bob_pub   = keypair_bob

    alice_token = register_login(client, 'alice3')
    bob_token   = register_login(client, 'bob3')
    eve_token   = register_login(client, 'eve3')

    bob_pub_pem = serialize_public_key(bob_pub).decode()
    client.post('/keys/upload',
                json={'public_key_pem': bob_pub_pem},
                headers={'Authorization': f'Bearer {bob_token}'})

    me_res = client.get('/auth/me', headers={'Authorization': f'Bearer {bob_token}'})
    bob_id = json.loads(me_res.data)['id']

    alice_priv_pem = serialize_private_key(alice_priv).decode()
    res = client.post('/files/encrypt-upload',
                      data={
                          'recipient_id':           str(bob_id),
                          'sender_private_key_pem': alice_priv_pem,
                          'file': (io.BytesIO(b'secret'), 'file.txt')
                      },
                      content_type='multipart/form-data',
                      headers={'Authorization': f'Bearer {alice_token}'})
    file_id = json.loads(res.data)['file_id']

    # Eve tries to decrypt
    eve_priv, _ = generate_rsa_keypair()
    dec_res = client.post(f'/files/decrypt/{file_id}',
                          json={
                              'recipient_private_key_pem': serialize_private_key(eve_priv).decode(),
                              'sender_public_key_pem':     serialize_public_key(alice_pub).decode()
                          },
                          headers={'Authorization': f'Bearer {eve_token}'})
    assert dec_res.status_code == 403
