import base64
# For Encoding / Decoding the salt
from base64 import b64encode, b64decode
# For Encrpyting / Decrpyting
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

class secureUtil():
    # Usage - Return password from json in memory
    def retrievePassword(self):
        data = json.loads(open("user.json", "r").read())
        return data["password"]

    # Usage - Return salt from json in memory
    def retrieveSalt(self):
        data = json.loads(open("user.json", "r").read())
        hold = b64decode(data["salt"])
        return hold
    """
    Usage: Takes in data variable non encoded and encrypts data
    Return Value: returns encrypted data non byte encoded
    Notes: This can be used when reading from json file, to encrypt that data then return json writeable data
    """
    def Encrypt(self, data):
        #Encrypt data passed
        data = data.encode('utf-8')
        #password = get password
        password = self.retrievePassword().encode('utf-8')
        #Retreive salt
        salt = self.retrieveSalt()
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
    Notes: This can be used when reading from json file, to decrypt that data then return readable data
    """
    def Decrypt(self, data):
        data = data.encode('utf-8')
        #password = get password
        password = self.retrievePassword().encode('utf-8')
        #Retreive salt
        salt = self.retrieveSalt()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(key)
        token = f.decrypt(data)
        return token.decode('utf-8')