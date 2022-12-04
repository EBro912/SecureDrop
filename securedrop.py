import json
import os.path
import pwinput
import bcrypt
import base64
# For Encoding / Decoding the salt
from base64 import b64encode, b64decode
# For Encrpyting / Decrpyting
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# For urandom
import os

# Sockets
from socketFunctionality import serverObject, clientObject


#-------------------------------------------------
#
# libraries used:
# pwinput: https://pypi.org/project/pwinput/
# bcrypt: https://pypi.org/project/bcrypt/
# cryptography: https://cryptography.io/
#
#-------------------------------------------------

class User:
    # don't store the password in memory
    def __init__(self, name, email):
        self.name = name
        self.email = email



# Usage - Return password from json in memory
def retrievePassword():
    data = json.loads(open("user.json", "r").read())
    return data["password"]

# Usage - Return salt from json in memory
def retrieveSalt():
    data = json.loads(open("user.json", "r").read())
    hold = b64decode(data["salt"])
    return hold


"""
    Usage: Takes in data variable non encoded and encrypts data
    Return Value: returns encrypted data non byte encoded
    Notes: This can be used when reading from json file, to encrypt that data then return json writeable data
"""
def Encrypt(data):
    #Encrypt data passed
    data = data.encode('utf-8')
    #password = get password
    password = retrievePassword().encode('utf-8')
    #Retreive salt
    salt = retrieveSalt()
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
def Decrypt(data):
    data = data.encode('utf-8')
    #password = get password
    password = retrievePassword().encode('utf-8')
    #Retreive salt
    salt = retrieveSalt()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.decrypt(data)
    return token.decode('utf-8')


def handleHelp():
    print('  "add" -> Add a new contact')
    print('  "list" -> List all online contacts')
    print('  "send" -> Transfer file to contact')
    print('  "exit" -> Exit SecureDrop')

def handleAdd():
    name = input('Enter Full Name: ')
    email = input('Enter Email Address: ')
    # ensure the user cannot add themselves
    global local_user
    if name == local_user.name or email == local_user.email:
        print("You may not add yourself as a contact.")
        return
    global contact_cache
    # ensure the user doesn't already exist
    name = Encrypt(name)
    email = Encrypt(email)
    if contact_cache is not None:
        for user in contact_cache:
            if user.name == name or user.email == email:
                # update contact entry if it exists
                user.name = name
                user.email = email
                print('Contact Updated.')
                return
    # use the User class to also store contacts
    contact_cache.append(User(name, email))
    print('Contact Added.')
    saveContacts()

def handleList():
    print('  The following contacts are online:')
    # TODO: retrieve online contacts (Milestone 4)
    # for now just treat everyone like they're online for testing purposes
    global contact_cache
    for user in contact_cache:
        print(f"  * {Decrypt(user.name)} <{Decrypt(user.email)}>")

def handleSend():
    temporary_socket_object = clientObject()
    file_path_or_data_idk = input("Enter path or data idk: ")
    temporary_socket_object.sendDataToServer(file_path_or_data_idk)
    temporary_socket_object.closeConnection()
    del temporary_socket_object 

def loadContacts():
    if os.path.exists("contacts.json") is False or os.path.getsize("contacts.json") == 0:
        return []
    data = json.loads(open("contacts.json", "r").read())
    contacts = []
    for user in data:
        # data is already encrypted here so just load it as is
        # good to store the data encrypted in memory as an attacker
        # could just look at the memory if they were stored decrypted
        contacts.append(User(user['name'], user['email']))
    return contacts

# save entire contact cache at once
def saveContacts():
    global contact_cache
    with open('contacts.json', 'w') as output:
        output.write(json.dumps([x.__dict__ for x in contact_cache]))


def createUser():
    name = input('Enter Full Name: ')
    email = input('Enter Email Address: ')
    password = pwinput.pwinput()
    reenter = pwinput.pwinput('Re-enter Password: ')
    if password != reenter:
        print("Passwords Do Not Match.")
    else:
        print("Passwords Match.")
        enc_pass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        # This is the salt used individually for each user, it is okay to store it in plaintext as it is only
        # used to stop rainbow table attacks
        salt = os.urandom(16)
        # Makes it storable in json,its random bytes so cant just use decode
        salt = b64encode(salt).decode('utf-8')
        with open("user.json", "w") as output:
            output.write(json.dumps({"name": name, "email": email, "password": enc_pass, "salt": salt}))
        print("User Registered.")

def loadUser():
    if os.path.exists("user.json") is False or os.path.getsize("user.json") == 0:
        return None
    # TODO: decrypt file here after above encryption
    data = json.loads(open("user.json", "r").read())
    # if the user.json file is wrong, treat it as if the user file doesn't exist
    if data["name"] is None or data["email"] is None or data["password"] is None:
        return None
    while True:
        entered_email = input('Enter Email Address: ')
        entered_password = pwinput.pwinput('Enter Password: ')
        if entered_email != data["email"] or bcrypt.checkpw(entered_password.encode('utf-8'), str(data["password"]).encode('utf-8')) is False:
            print('Email and Password Combination Invalid.')
        else:
            break
    # dont store the users password in this object, as it isnt needed anymoren
    return User(data["name"], data["email"])

# store user name and email for later use
local_user = loadUser()

# also cache all of our existing contacts
# please do NOT name a variable the same as this or the program will break!
contact_cache = loadContacts()

if local_user is None:
    create = input('No users are registered with this client.\nDo you want to register a new user (y/n)? ').lower()
    # only do anything if the user inputs yes
    if create == 'y':
        createUser()
    print("Exiting SecureDrop.")
    exit()

print('Welcome to SecureDrop.\nType "help" for commands.\n')

# run command logic until the user exits
while True:
    # read in the user's command and parse it as lowercase to make things easier
    command = input("secure_drop> ").lower()
    if command == "help":
        handleHelp()
    elif command == "add":
        handleAdd()
    elif command == "list":
        handleList()
    elif command == "send":
        handleSend()
    elif command == "exit":
        break
    else:
        print('Unknown command.\nType "help" for commands.\n')