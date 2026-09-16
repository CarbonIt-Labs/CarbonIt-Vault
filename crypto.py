import base64
import json
import os
import hashlib
from pathlib import Path

from argon2.low_level import hash_secret_raw, Type
from quantcrypt.kem import MLKEM_1024
from quantcrypt.cipher import Krypton


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def password_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 64-byte high-cost key from the master password and vault salt."""
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=128 * 1024,  # 128 MiB
        parallelism=2,
        hash_len=64,
        type=Type.ID,
    )


def krypton_encrypt(key: bytes, plaintext: bytes) -> dict:
    cipher = Krypton(key)
    cipher.begin_encryption()
    ciphertext = cipher.encrypt(plaintext)
    verification = cipher.finish_encryption()
    return {
        "ciphertext": b64(ciphertext),
        "verification": b64(verification),
    }


def krypton_decrypt(key: bytes, packet: dict) -> bytes:
    cipher = Krypton(key)
    cipher.begin_decryption(unb64(packet["verification"]))
    plaintext = cipher.decrypt(unb64(packet["ciphertext"]))
    cipher.finish_decryption()
    return plaintext


def make_vault_key(password_key_bytes: bytes, pq_shared_secret: bytes) -> bytes:
    # Domain separation keeps this combination specific to the vault key.
    return hashlib.sha3_512(
        b"CARBONIT-VAULT-V1|" + password_key_bytes + pq_shared_secret
    ).digest()


def create_vault(master_password: str) -> tuple[dict, bytes]:
    salt = os.urandom(16)
    pwd_key = password_key(master_password, salt)

    # NIST-standardized ML-KEM-1024 through QuantCrypt.
    kem = MLKEM_1024()
    public_key, secret_key = kem.keygen()
    kem_ciphertext, shared_secret = kem.encaps(public_key)

    vault_key = make_vault_key(pwd_key, shared_secret)

    # Protect the ML-KEM secret key with a password-derived symmetric key.
    encrypted_secret_key = krypton_encrypt(pwd_key, secret_key)

    entries = []
    encrypted_vault = krypton_encrypt(
        vault_key,
        json.dumps(entries, separators=(",", ":")).encode("utf-8"),
    )

    vault_data = {
        "version": 1,
        "algorithm": "ML-KEM-1024 + Argon2id + QuantCrypt-Krypton",
        "salt": b64(salt),
        "kem_public_key": b64(public_key),
        "kem_ciphertext": b64(kem_ciphertext),
        "encrypted_kem_secret_key": encrypted_secret_key,
        "vault": encrypted_vault,
    }
    
    return vault_data, vault_key


def unlock_vault(path: Path, master_password: str) -> tuple[dict, bytes]:
    raw = json.loads(path.read_text(encoding="utf-8"))

    salt = unb64(raw["salt"])
    pwd_key = password_key(master_password, salt)

    secret_key = krypton_decrypt(
        pwd_key, raw["encrypted_kem_secret_key"]
    )

    kem = MLKEM_1024()
    shared_secret = kem.decaps(
        secret_key,
        unb64(raw["kem_ciphertext"]),
    )

    vault_key = make_vault_key(pwd_key, shared_secret)
    plaintext = krypton_decrypt(vault_key, raw["vault"])
    entries = json.loads(plaintext.decode("utf-8"))

    # Return the disk metadata plus the active key.
    return {"raw": raw, "entries": entries}, vault_key


def save_unlocked_vault(path: Path, raw: dict, entries: list, vault_key: bytes) -> None:
    raw = dict(raw)
    raw["vault"] = krypton_encrypt(
        vault_key,
        json.dumps(entries, separators=(",", ":")).encode("utf-8"),
    )

    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    os.replace(tmp, path)