"""
keygen.py — Generate RSA-2048 key pairs for CryptoShield users.

Usage:
    python keygen.py --name alice
    python keygen.py --name bob

Outputs:
    keys/alice_private.pem  (keep secret, never upload)
    keys/alice_public.pem   (upload to /keys/upload endpoint)
"""

import argparse
import os
from app.crypto_engine import (
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key
)


def main():
    parser = argparse.ArgumentParser(description='Generate RSA-2048 key pair for CryptoShield')
    parser.add_argument('--name', required=True, help='User name for key file prefix')
    parser.add_argument('--outdir', default='keys', help='Output directory (default: keys/)')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    print(f'[*] Generating RSA-2048 key pair for: {args.name}')
    private_key, public_key = generate_rsa_keypair()

    priv_path = os.path.join(args.outdir, f'{args.name}_private.pem')
    pub_path  = os.path.join(args.outdir, f'{args.name}_public.pem')

    with open(priv_path, 'wb') as f:
        f.write(serialize_private_key(private_key))

    with open(pub_path, 'wb') as f:
        f.write(serialize_public_key(public_key))

    print(f'[+] Private key saved to: {priv_path}')
    print(f'[+] Public key saved to:  {pub_path}')
    print()
    print('[!] IMPORTANT:')
    print('    - Keep your private key LOCAL. Never upload it anywhere.')
    print('    - Upload your PUBLIC key to CryptoShield: POST /keys/upload')
    print()

    # Print public key so it can be copy-pasted for upload
    with open(pub_path) as f:
        print('--- Your Public Key (upload this) ---')
        print(f.read())


if __name__ == '__main__':
    main()
