import socket
import os
from _thread import *
import ssl
import json
import pwinput
import bcrypt
from base64 import b64encode
from secureUtil import secureUtil

import pickle
#-------------------------------------------------
#
# libraries used:
# pwinput: https://pypi.org/project/pwinput/
# bcrypt: https://pypi.org/project/bcrypt/
# cryptography: https://cryptography.io/
#
#-------------------------------------------------

util = secureUtil()

class serverSide():
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 52000
        self.key_file = "keys/key.pem"
        self.cert_file = "keys/certificate.pem"
        self.server_socket = self.createSSLSocket()
        self.logged_in_users = []
        self.active_transfer = None

    """
    Usage: Creates a new SSL socket using a key and certificate
    Return Value: the newly created socket
    """
    def createSSLSocket(self):
        try:
            socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # the SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire.
            socket_object.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Wrap in ssl with our cert and private key , THIS ONLY WORKS WITH THE KEY YOU USED TO CREATE THE CERTIFICATE
            socket_object = ssl.wrap_socket(socket_object, keyfile=self.key_file, certfile=self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1_2)
            return socket_object
        except socket.error as error:
            print("Socket creation failed with error code: '{0}'".format(error))

    """
    Usage: Starts the server and begins listening for new connections
    Return Value: None
    """
    def startServer(self):
        try:
            self.server_socket.bind((self.host,self.port))
        except socket.error as e:
            print(str(e))
        print("Server is listening on port {0}".format(self.port))
        self.server_socket.listen()
        while True:
            self.handleConnections()

    """
    Usage: Enters a user into the logged_in_users array when they log in using the provided data
    Return Value: None
    """
    def handleReceivingContacts(self, data, connection):
        # unpickle user login data
        pickle_object = pickle.loads(data)
        pickle_object.client = connection
        # add the user to the list of logged in users
        self.logged_in_users.append(pickle_object)

    """
    Usage: Updates a user's contacts on the server when they add a user to their contacts
    Return Value: None
    """
    def handleUpdateContacts(self, data):
        # unpickle user login data
        pickle_object = pickle.loads(data)
        for user in self.logged_in_users:
            if user.name == pickle_object.name and user.email == pickle_object.email:
                user.contacts = pickle_object.contacts
                return

    """
    Usage: Retrieves information related to which contacts are online
    Return Value: A list of contacts that are online
    """
    def checkOnlineUser(self, data):
        pickle_object = pickle.loads(data)
        online_users = "  The following contacts are online:"
        target = None
        # Search for the sender's contact list
        for user in self.logged_in_users:
            if user.name == pickle_object.name and user.email == pickle_object.email:
                target = user
                break
        if target is None:
            print("Error: Could not find target user with data " + pickle_object)
            return
        #check every contact in sender's list
        for contact in target.contacts:
            name = util.Decrypt(contact.name, target.password, target.salt)
            email = util.Decrypt(contact.email, target.password, target.salt)
            #if the contact is online
            if self.isUserLoggedIn(name,email):
                #search for contact's contact list
                for user in self.logged_in_users:
                    if user.name == name and user.email == email:
                        for contact in user.contacts:
                            contactName = util.Decrypt(contact.name, user.password, user.salt)
                            contactEmail = util.Decrypt(contact.email, user.password, user.salt)
                            #if the sender's info is in the contact's list, add the contact to sender's list
                            if contactName == target.name and contactEmail == target.email:
                                online_users += "\n  * {0} <{1}>".format(name, email)
                                break
        return online_users.encode()

    """
    Usage: Checks if a user is valid to send a file to 
    Return Value: None
    """
    def checkAvailableUser(self, connection):
        #receive sender's information
        data = connection.recv(2048)
        source = pickle.loads(data)
        
        data = connection.recv(2048)
        target = pickle.loads(data)

        if self.active_transfer is not None:
            connection.send("BUSY".encode())
            return

        sourceInContacts = False
        targetInContacts = False
        user_source = None
        user_target = None

        for user in self.logged_in_users:
            if user.name == source.name and user.email == source.email:
                user_source = user
                break
        #find receiver in list to get it's contacts
        for user in self.logged_in_users:
            if user.email == target:
                user_target = user
                break

        # if the target or source (somehow) doesn't exist, return failure
        if user_source is None or user_target is None:
            user_source.client.send("SEND FAIL".encode())

        #search for receiver in sender's contact list
        for contact in user_source.contacts:
            name = util.Decrypt(contact.name, user_source.password, user_source.salt)
            email = util.Decrypt(contact.email, user_source.password, user_source.salt)
            if name == user_target.name and email == user_target.email:
                targetInContacts = True
        #search for sender in receiver's contact list
        for contact in user_target.contacts:
            name = util.Decrypt(contact.name, user_target.password, user_target.salt)
            email = util.Decrypt(contact.email, user_target.password, user_target.salt)
            if name == user_source.name and email == user_source.email:
                sourceInContacts = True

        if user_target is not None and self.isUserLoggedIn(user_target.name,user_target.email) and targetInContacts and sourceInContacts:
            user_target.client.send("FILE".encode())
            # send who is sending the file
            temp_pickle_string = pickle.dumps(User(user_source.name, user_source.email))
            user_target.client.send(temp_pickle_string)
            self.active_transfer = [user_source, user_target]
        else:
            user_source.client.send("SEND FAIL".encode())
        
    """
    Usage: Removes a user from the logged in users list. This assumes that only one user with the given name and email exists at a time
    Return Value: None
    """
    def handleLogout(self, data):
        pickle_object = pickle.loads(data)
        for user in self.logged_in_users:
            if user.name == pickle_object.name and user.email == pickle_object.email:
                self.logged_in_users.remove(user)
                return

    """
    Usage: Checks if a user is currently "logged in"
    Return Value: True if they are, False if not
    """
    def isUserLoggedIn(self, name, email):
        return any(x.name == name and x.email == email for x in self.logged_in_users)

    """
    Usage: Handles incoming requests from a client
    Return Value: None
    """
    def handleClient(self,connection):
        while True:
            data = connection.recv(2048)
            message = data.decode('utf-8')
            if message == "EXIT":
                data = connection.recv(2048)
                self.handleLogout(data)
                connection.close()
            elif message == "LOGIN":
                # Pass raw data, this is receving the pickled object
                data = connection.recv(2048)
                self.handleReceivingContacts(data, connection)
            elif message == "UPDATE CONTACTS":
                data = connection.recv(2048)
                self.handleUpdateContacts(data)
            elif message == "LIST USERS":
                # Check if users are online from users contact, send them user object
                data = connection.recv(2048)
                connection.send(self.checkOnlineUser(data))
            elif message == "SEND":
                self.checkAvailableUser(connection)
            elif message == "SEND FILE":
                # get the size and filepath of the file being sent
                size = int.from_bytes(connection.recv(4), 'big')
                filepath = connection.recv(2048).decode('utf-8')
                file = bytearray()
                # read all the bytes sent
                while size:
                        data = connection.recv(min(size, 4096))
                        size -= len(data)
                        file += bytearray(data)
                # send the read bytes over to the recipient
                self.active_transfer[1].client.send("RECEIVE FILE".encode())
                self.active_transfer[1].client.send(len(file).to_bytes(4, 'big'))
                self.active_transfer[1].client.send(filepath.encode())
                self.active_transfer[1].client.send(file)
            elif message == "FILE RECEIVED": 
                # after the file has been successfully sent, notify the sender
                self.active_transfer[0].client.send("SEND SUCCESS".encode())
                self.active_transfer = None
            elif message == "ACCEPT":
                self.active_transfer[0].client.send("SEND ACCEPTED".encode())
            elif message == "DECLINE":               
                self.active_transfer[0].client.send("SEND DECLINED".encode())
                self.active_transfer = None
            elif message == "SHUTDOWN":
                print("Shutting Down Server ...")
                connection.sendall("Shutdown Initiated. Goodbye!".encode())
                connection.close()
                # Unclean
                os._exit(1)

    """
    Usage: Receives a connection request and starts a new thread to handle their requests
    Return Value: None
    """
    def handleConnections(self):
        client, address = self.server_socket.accept()
        print("Connected to: {0}:{1}".format(address[0],str(address[1])))
        # Not sure what went wrong, reverted back to old threading - Alex
        start_new_thread(self.handleClient, (client,))

# user object
class User:
    # don't store the password in memory
    def __init__(self, name, email):
        self.name = name
        self.email = email

# For combining contacts and User object, as well as other data for encryption purposes
# Note: password here is encrypted
class ServerUser:
    def __init__(self, name, email, contacts, password, salt):
        self.name = name
        self.email = email
        self.contacts = contacts
        self.password = password
        self.salt = salt
        self.client = None

# Client side
class clientSide():
    def __init__(self):
        self.connect_to_host = '127.0.0.1'
        self.connect_to_port = 52000
        self.cert_file = "keys/certificate.pem"
        self.key_file = "keys/key.pem"
        self.client_socket = self.createSSLSocket()
        self.local_user = self.loadUser()
        self.contacts = self.loadContacts()

    """
    Usage: Sends a user's contacts and other information to the server for later use
    Return Value: None
    """
    def sendObjectToServer(self):
        data = json.loads(open("user.json", "r").read())
        temp = ServerUser(self.local_user.name,self.local_user.email,self.contacts, data["password"], data["salt"])
        temp_pickle_string = pickle.dumps(temp)
        self.client_socket.send(temp_pickle_string)

    """
    Usage: Requests a logout from the server
    Return Value: None
    """
    def sendLogoutToServer(self):
        temp_pickle_string = pickle.dumps(self.local_user)
        self.client_socket.send("EXIT".encode())
        self.client_socket.send(temp_pickle_string)

    """
    Usage: Creates a new user if one doesn't exist
    Return Value: None
    """
    def createUser(self):
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

    """
    Usage: Loads a user's information
    Return Value: A new User object containing their data, or None if it doesnt exist
    """
    def loadUser(self):
        if os.path.exists("user.json") is False or os.path.getsize("user.json") == 0:
            return None
        data = json.loads(open("user.json", "r").read())
        # if the user.json file is wrong, treat it as if the user file doesn't exist
        if data["name"] is None or data["email"] is None or data["password"] is None:
            return None
        while True:
            entered_email = input('Enter Email Address: ')
            entered_password = pwinput.pwinput('Enter Password: ')
            if entered_email != data["email"] or bcrypt.checkpw(entered_password.encode('utf-8'), str(data["password"]).encode('utf-8')) is False:
                print('Email and Password Combination Invalid.\n')
            else:
                break
        # dont store the users password in this object, as it isnt needed anymore
        return User(data["name"], data["email"])

    """
    Usage: Loads a user's contacts
    Return Value: An array of User objects for each contact, or an empty array if they dont have any
    """
    def loadContacts(self):
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

    """
    Usage: Saves a user's contacts to the filesystem
    Return Value: None
    """
    def saveContacts(self):
        with open('contacts.json', 'w') as output:
            output.write(json.dumps([x.__dict__ for x in self.contacts]))
        self.client_socket.send("UPDATE CONTACTS".encode())
        self.sendObjectToServer()

    """
    Usage: Handles adding a contact to the user's contacts
    Return Value: None
    """
    def handleAdd(self):
        name = input('  Enter Full Name: ')
        email = input('  Enter Email Address: ')
        # ensure the user cannot add themselves
        data = json.loads(open("user.json", "r").read())
        if name == self.local_user.name or email == self.local_user.email:
            print("You may not add yourself as a contact.")
            return
        # ensure the user doesn't already exist
        name = util.Encrypt(name, data["password"], data["salt"])
        email = util.Encrypt(email, data["password"], data["salt"])
        if self.contacts is not None:
            for user in self.contacts:
                if user.name == name or user.email == email:
                    # update contact entry if it exists
                    user.name = name
                    user.email = email
                    print('Contact Updated.')
                    return
        # use the User class to also store contacts
        self.contacts.append(User(name, email))
        print('  Contact Added.')
        self.saveContacts()
    
    """
    Usage: Handles listing out a user's online contacts
    Return Value: None
    """
    def handleList(self):
        self.client_socket.send("LIST USERS".encode())
        # Debugging - Alex
        # print(self.contacts[0].name)
        pickle_message = pickle.dumps(self.local_user)
        self.client_socket.send(pickle_message)
        response = self.client_socket.recv(2048)
        print(response.decode())

    """
    Usage: Handles sending a file to another user
    Return Value: None
    """
    def handleSend(self,receiver,file_path):
        if not os.path.exists(file_path):
            print("Send failed, filepath does not exist.")
            return
        self.client_socket.send("SEND".encode())
        # Debugging - Alex
        # print(self.contacts[0].name)

        #send local user 
        pickle_message = pickle.dumps(self.local_user)
        self.client_socket.send(pickle_message)

        #send the email of the receiving user
        pickle_message = pickle.dumps(receiver)
        self.client_socket.send(pickle_message)

        data = self.client_socket.recv(2048)
        message = data.decode('utf-8')
        if message == "BUSY":
            print("The server is busy with another file transfer. Please wait.")
        elif message == "SEND FAIL":
            print("File send failed. Contact is either not online, not in your contacts, or is busy.")
        elif message == "SEND ACCEPTED":
            print("Contact has accepted the transfer request.")
            with open(file_path, 'rb') as file:
                # send the file to the server as well as information related to the file
                bytes = file.read()
                self.client_socket.send("SEND FILE".encode())
                self.client_socket.send(len(bytes).to_bytes(4, 'big'))
                self.client_socket.send(os.path.basename(file_path).encode())
                self.client_socket.send(bytes)
            
            data = self.client_socket.recv(2048)
            message = data.decode('utf-8')
            if message == "SEND SUCCESS":
                print("File has been successfully transferred.")
            
        elif message == "SEND DECLINED":
            print("Contact has declined the transfer request.")
            

    """
    Usage: Handles receiving a file from another user
    Return Value: None
    """
    def handleReceive(self):
        print('Waiting for file requests...')
        # wait until we get a request
        data = self.client_socket.recv(2048)
        message = data.decode('utf-8')
        if message == "FILE":
            data = self.client_socket.recv(2048)
            user = pickle.loads(data)
            choice = input("Contact {0} <{1}> is sending a file. Accept? (y/n) ".format(user.name, user.email)).lower()
            if choice == "y":
                print('Accepted file transfer. Receiving file...')
                self.client_socket.send("ACCEPT".encode())
                data = self.client_socket.recv(2048)
                message = data.decode('utf-8')
                if message == "RECEIVE FILE":
                    # read information about the file
                    size = int.from_bytes(self.client_socket.recv(4), 'big')
                    filepath = self.client_socket.recv(2048).decode('utf-8')
                    print(filepath)
                    print(size)
                    with open(filepath, 'wb') as file:
                        # keep receiving bytes until the entire file has been read
                        while size:
                            data = self.client_socket.recv(min(size, 4096))
                            size -= len(data)
                            file.write(data)              
                print("File recevied successfully. ({0} | {1} bytes)".format(filepath, size))
                self.client_socket.send("FILE RECEIVED".encode())
            else:
                print('Declined file transfer.')
                self.client_socket.send("DECLINE".encode())

    
    """
    Usage: Creates a new SSL socket using a key and certificate
    Return Value: the newly created socket
    """
    def createSSLSocket(self):
        try:
            socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # the SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire.
            socket_object.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Wrap in ssl with our cert and using TLS v1.2 or Greater
            socket_object = ssl.wrap_socket(socket_object, keyfile=self.key_file, certfile=self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1_2)
            #print("Socket created successfully ...")
            return socket_object
        except socket.error as error:
            print("Socket creation failed with error code: '{0}'".format(error))

    
    """
    Usage: Handles starting up the client and connecting to the server
    Return Value: None
    """
    def startClient(self):
        if self.local_user is None:
            create = input('No users are registered with this client.\nDo you want to register a new user (y/n)? ').lower()
            # only do anything if the user inputs yes
            if create == 'y':
                self.createUser()
            print("Exiting SecureDrop.")
            exit()
        try:
            self.client_socket.connect((self.connect_to_host,self.connect_to_port))
        except socket.error as e:
            print(str(e))
        # send our information to the server when we log in
        self.client_socket.send("LOGIN".encode())
        self.sendObjectToServer()
        print('Welcome to SecureDrop.\nType "help" for commands.\n')
        self.handleUI()

    """
    Usage: The main secure_drop terminal, which handles input
    Return Value: None
    """
    def handleUI(self):
        while True:
            data = input("secure_drop> ").split(' ')
            choice = data[0].lower()
            if len(data) > 1:
                args = data[1:]
            if choice == "help":
                print('  "add" -> Add a new contact')
                print('  "list" -> List all online contacts')
                print('  "send" -> Transfer file to contact')
                print('  "receive" -> Receive a file from contacts')
                print('  "exit" -> Exit SecureDrop')
            elif choice == "exit":
                self.sendLogoutToServer()
                self.client_socket.close()
                exit()
            elif choice == "add":
                self.handleAdd()
            elif choice == "list":
                self.handleList()
            # TODO: make this require a contact and path parameter
            # as per the requirements
            elif choice == "send":
                if len(args) < 2:
                    print('Usage: send <contact> <filepath>')
                else:
                    receiver = args[0]
                    file_path = args[1]
                    self.handleSend(receiver,file_path)
            elif choice == "receive":
                self.handleReceive()
            else:
                print('Unknown command.\nType "help" for commands.\n')
