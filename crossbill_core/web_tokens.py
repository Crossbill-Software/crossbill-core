import datetime
import enum
import logging

import jwt

logger = logging.getLogger(__name__)

class EncryptDecryptErrorCode(enum.Enum):

    ERROR_NONE = 0
    ERROR_ENCRYPT_FAILED = 1
    ERROR_DECRYPT_FAILED = 2
    ERROR_DECRYPT_DECODE_ERROR = 3
    ERROR_DECRYPT_INVALID_TOKEN_ERROR = 4
    ERROR_DECRYPT_TOKEN_EXPIRED = 5

class JsonWebToken(object):
    """Represents a json web token."""

    ALGORITHM = 'HS256'
    DEFAULT_TOKEN_EXPIRATION_DELTA_IN_SECONDS = 60 * 60 # 1 hour
    EXPIRATION_FIELD_NAME = 'exp'

    def __init__(self, token: str):

        self.token = token

    def __str__(self):

        return self.token

    def __repr__(self):

        return f'<{self.__class__.__name__} {self.token}>'

    @classmethod
    def generate_expiration_time(cls):
        now = datetime.datetime = datetime.datetime.now(tz=datetime.timezone.utc)
        delta : datetime.timedelta = datetime.timedelta(seconds=cls.DEFAULT_TOKEN_EXPIRATION_DELTA_IN_SECONDS)
        expiration_date : datetime.datetime = now + delta
        return int(expiration_date.timestamp())

    @classmethod
    def decrypt(cls, encoded: str, secret: str):
        """Decrypts a string using the private key.

        Returns EncryptDecryptErrorCode.ERROR_NONE on success.
        Returns EncryptDecryptErrorCode.ERROR_DECRYPT_FAILED on failure.

        Potentially more error codes in the future
        """

        error_code : EncryptDecryptErrorCode = EncryptDecryptErrorCode.ERROR_DECRYPT_FAILED
        decoded = None

        if not encoded or not isinstance(encoded, str):
            raise ValueError("Expected encoded to be of type str")

        if not secret or not isinstance(secret, str):
            raise ValueError("Invalid secret")

        try:

            decoded = jwt.decode(encoded, secret, cls.ALGORITHM)

        except jwt.exceptions.ExpiredSignatureError as error:
            logger.error(f"Expiry token error={error}")
            error_code = EncryptDecryptErrorCode.ERROR_DECRYPT_TOKEN_EXPIRED

        except jwt.exceptions.InvalidTokenError as error:

            logger.error(f"Invalid token error={error}")
            error_code = EncryptDecryptErrorCode.ERROR_DECRYPT_INVALID_TOKEN_ERROR

        except jwt.exceptions.DecodeError as error:
            logger.error(f"Decode token error={error}")
            error_code = EncryptDecryptErrorCode.ERROR_DECRYPT_DECODE_ERROR


        except Exception as error:

            logger.exception(f"Unknown Exception while decoding: {error}")

        else:
            error_code = EncryptDecryptErrorCode.ERROR_NONE

        return error_code, decoded



    @classmethod
    def encrypt(cls, payload: dict, secret: str):
        """Decrypts a string using the private key.

        Returns EncryptDecryptErrorCode.ERROR_NONE on success.
        Returns EncryptDecryptErrorCode.ERROR_ENCRYPT_FAILED on failure.

        Potentially more error codes in the future
        """

        error_code : EncryptDecryptErrorCode = EncryptDecryptErrorCode.ERROR_ENCRYPT_FAILED

        if not isinstance(payload, dict):
            raise ValueError("Expected payload to be of type dict")

        if not secret or not isinstance(secret, str):
            raise ValueError("Invalid secret")

        encoded = None

        try:

            encoded = jwt.encode(payload, secret, algorithm=cls.ALGORITHM)

        except Exception as error:

            logger.exception(f"Encoding failed: {error}")

        else:

            error_code = EncryptDecryptErrorCode.ERROR_NONE

        return error_code, cls(encoded)
