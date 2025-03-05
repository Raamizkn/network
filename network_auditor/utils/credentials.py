"""
Utilities for securely handling credentials.
"""

import os
import json
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from network_auditor.config import (
    USE_ENV_CREDENTIALS,
    ENV_USERNAME,
    ENV_PASSWORD,
    BASE_DIR,
)
from network_auditor.utils.logger import logger
from network_auditor.utils.exceptions import NetworkAuditorError


class CredentialError(NetworkAuditorError):
    """Exception raised when there is an error with credentials."""
    pass


class CredentialManager:
    """
    Manages secure storage and retrieval of credentials.
    """

    def __init__(self, use_env=USE_ENV_CREDENTIALS):
        """
        Initialize the credential manager.

        Args:
            use_env (bool, optional): Whether to use environment variables for credentials.
                Defaults to USE_ENV_CREDENTIALS from config.
        """
        self.use_env = use_env
        self.credentials_file = Path(BASE_DIR) / '.credentials'
        self.key_file = Path(BASE_DIR) / '.key'

    def _generate_key(self, password, salt=None):
        """
        Generate a key for encryption/decryption.

        Args:
            password (str): The password to derive the key from.
            salt (bytes, optional): The salt to use for key derivation. If None, a new salt is generated.

        Returns:
            tuple: (key, salt) where key is the derived key and salt is the salt used.
        """
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def _save_key(self, key, salt):
        """
        Save the encryption key and salt to a file.

        Args:
            key (bytes): The encryption key.
            salt (bytes): The salt used for key derivation.
        """
        with open(self.key_file, 'wb') as f:
            f.write(salt + b'\n' + key)

    def _load_key(self):
        """
        Load the encryption key and salt from a file.

        Returns:
            bytes: The encryption key.

        Raises:
            CredentialError: If the key file does not exist.
        """
        if not self.key_file.exists():
            raise CredentialError("Key file does not exist. Please set up credentials first.")
        with open(self.key_file, 'rb') as f:
            data = f.read().split(b'\n')
            salt = data[0]
            key = data[1]
        return key

    def setup_credentials(self, username, password, master_password):
        """
        Set up credentials for the first time.

        Args:
            username (str): The username to store.
            password (str): The password to store.
            master_password (str): The master password to encrypt the credentials.
        """
        key, salt = self._generate_key(master_password)
        self._save_key(key, salt)

        credentials = {
            'username': username,
            'password': password,
        }
        encrypted = self._encrypt(json.dumps(credentials), key)
        with open(self.credentials_file, 'wb') as f:
            f.write(encrypted)
        logger.info("Credentials set up successfully.")

    def _encrypt(self, data, key):
        """
        Encrypt data using the given key.

        Args:
            data (str): The data to encrypt.
            key (bytes): The encryption key.

        Returns:
            bytes: The encrypted data.
        """
        f = Fernet(key)
        return f.encrypt(data.encode())

    def _decrypt(self, data, key):
        """
        Decrypt data using the given key.

        Args:
            data (bytes): The data to decrypt.
            key (bytes): The decryption key.

        Returns:
            str: The decrypted data.
        """
        f = Fernet(key)
        return f.decrypt(data).decode()

    def get_credentials(self, master_password=None):
        """
        Get the stored credentials.

        Args:
            master_password (str, optional): The master password to decrypt the credentials.
                Required if not using environment variables.

        Returns:
            dict: A dictionary containing 'username' and 'password'.

        Raises:
            CredentialError: If credentials cannot be retrieved.
        """
        if self.use_env:
            username = os.environ.get(ENV_USERNAME)
            password = os.environ.get(ENV_PASSWORD)
            if not username or not password:
                raise CredentialError(
                    f"Environment variables {ENV_USERNAME} and {ENV_PASSWORD} must be set."
                )
            return {'username': username, 'password': password}
        else:
            if not master_password:
                raise CredentialError("Master password is required to decrypt credentials.")
            if not self.credentials_file.exists():
                raise CredentialError("Credentials file does not exist. Please set up credentials first.")
            key = self._load_key()
            with open(self.credentials_file, 'rb') as f:
                encrypted = f.read()
            try:
                decrypted = self._decrypt(encrypted, key)
                return json.loads(decrypted)
            except Exception as e:
                raise CredentialError(f"Failed to decrypt credentials: {str(e)}")

    def credentials_exist(self):
        """
        Check if credentials have been set up.

        Returns:
            bool: True if credentials exist, False otherwise.
        """
        if self.use_env:
            return ENV_USERNAME in os.environ and ENV_PASSWORD in os.environ
        else:
            return self.credentials_file.exists() and self.key_file.exists() 