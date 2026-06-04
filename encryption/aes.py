"""AES encryption helpers for Q-SAFE Nexus."""

from pathlib import Path
from os import urandom

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12
KEY_SIZE_BITS = 256


def generate_key() -> bytes:
    """Generate a secure random AES-256 key."""
    return AESGCM.generate_key(bit_length=KEY_SIZE_BITS)


def encrypt_file(file_path, key: bytes) -> Path:
    """Encrypt a file with AES-GCM and save the result as a .enc file."""
    source_path = Path(file_path)
    encrypted_path = source_path.with_name(f"{source_path.name}.enc")

    # AES-GCM requires a unique nonce for every encryption operation.
    nonce = urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    file_data = source_path.read_bytes()
    encrypted_data = aesgcm.encrypt(nonce, file_data, None)

    # Store nonce with ciphertext so decrypt_file can reconstruct the operation.
    encrypted_path.write_bytes(nonce + encrypted_data)
    return encrypted_path


def decrypt_file(file_path, key: bytes) -> Path:
    """Decrypt a .enc file and save the plaintext beside it."""
    encrypted_path = Path(file_path)
    encrypted_payload = encrypted_path.read_bytes()

    nonce = encrypted_payload[:NONCE_SIZE]
    encrypted_data = encrypted_payload[NONCE_SIZE:]
    aesgcm = AESGCM(key)

    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)

    if encrypted_path.suffix == ".enc":
        decrypted_path = encrypted_path.with_suffix("")
    else:
        decrypted_path = encrypted_path.with_name(f"{encrypted_path.name}.dec")

    decrypted_path.write_bytes(decrypted_data)
    return decrypted_path
