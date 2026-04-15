from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet


class EncryptedFileStorage:
    def __init__(self, key_file: str | Path) -> None:
        self.key_file = Path(key_file)
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

    def _load_or_create_key(self) -> bytes:
        if self.key_file.exists():
            return self.key_file.read_bytes()

        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        return key

    def encrypt_bytes(self, data: bytes) -> bytes:
        # This will be used when we switch document uploads from plain file.save(...) to encrypted storage.
        return self.cipher.encrypt(data)

    def decrypt_bytes(self, data: bytes) -> bytes:
        # This will be used later during authorized downloads so the user gets the original file contents back.
        return self.cipher.decrypt(data)

    def encrypt_to_file(self, destination: str | Path, data: bytes) -> Path:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.encrypt_bytes(data))
        return destination

    def decrypt_from_file(self, source: str | Path) -> bytes:
        source = Path(source)
        return self.decrypt_bytes(source.read_bytes())
