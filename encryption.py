from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet

#This file is responsible for encrypting and decrypting files using Fernet symmetric encryption. 
#It provides methods to encrypt and decrypt byte data, as well as to encrypt data directly to a file 
#and decrypt data from a file. The encryption key is stored in a specified key file, which is created 
#if it does not already exist.

#The EncryptedFileStorage class manages the encryption and decryption processes, 
#ensuring that files are securely stored and can be retrieved in their original form when needed.
class EncryptedFileStorage:
    def __init__(self, key_file: str | Path) -> None:
        self.key_file = Path(key_file)
        self.key_file.parent.mkdir(parents=True, exist_ok=True)
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

    #This method checks if the key file exists. If it does, it reads and returns the key.
    #If the key file does not exist, it generates a new key, saves it to the file, and returns the new key.
    def _load_or_create_key(self) -> bytes:
        if self.key_file.exists():
            return self.key_file.read_bytes()

        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        return key

    #The encrypt_bytes method takes byte data as input and returns the encrypted version of that data 
    #using the Fernet cipher.
    def encrypt_bytes(self, data: bytes) -> bytes:
        # This will be used when we switch document uploads from plain file.save(...) to encrypted storage.
        return self.cipher.encrypt(data)

    #The decrypt_bytes method takes encrypted byte data as input and returns the original byte data 
    #by decrypting it using the Fernet cipher.
    def decrypt_bytes(self, data: bytes) -> bytes:
        # This will be used later during authorized downloads so the user gets the original file contents back.
        return self.cipher.decrypt(data)

    #The encrypt_to_file method takes a destination path and byte data, encrypts the data, and writes 
    #it to the specified file.
    def encrypt_to_file(self, destination: str | Path, data: bytes) -> Path:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.encrypt_bytes(data))
        return destination

    #The decrypt_from_file method takes a source path, reads the encrypted data from the file, 
    #decrypts it, and returns the original byte data.
    def decrypt_from_file(self, source: str | Path) -> bytes:
        source = Path(source)
        return self.decrypt_bytes(source.read_bytes())
