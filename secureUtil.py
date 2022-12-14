import base64
# For Encoding / Decoding the salt
from base64 import b64decode
# For Encrpyting / Decrpyting
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Util class for encryption related functions
class secureUtil():
    """
    Usage: Takes in data variable non encoded and encrypts data
    Return Value: returns encrypted data non byte encoded
    """
    def Encrypt(self, data, passwd, salt):
        #Encrypt data passed
        data = data.encode('utf-8')
        #password = get password
        password = passwd.encode('utf-8')
        #Retreive salt
        salt = b64decode(salt)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        token = f.encrypt(data)
        return token.decode('utf-8')


    """
    Usage: Takes in data variable non encoded and decrypts data
    Return Value: returns decrypted data non byte encoded
    """
    def Decrypt(self, data, passwd, salt):
        data = data.encode('utf-8')
        #password = get password
        password = passwd.encode('utf-8')
        #Retreive salt
        salt = b64decode(salt)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        token = f.decrypt(data)
        return token.decode('utf-8')