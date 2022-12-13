import socket
import os
from _thread import *
import ssl
import json
import pwinput
import bcrypt
from base64 import b64encode, b64decode
from secureUtil import secureUtil
# from threading import Thread
import sys

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
    # If the filepath changes, or you wnat to change port/ host etc
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 52000
        self.key_file = "keys/key.pem"
        self.cert_file = "keys/certificate.pem"
        self.server_socket = self.createSSLSocket()
        self.logged_in_users = []

    # Creates SSL wrapped socket
    def createSSLSocket(self):
        try:
            socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # the SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire.
            socket_object.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Wrap in ssl with our cert and private key , THIS ONLY WORKS WITH THE KEY YOU USED TO CREATE THE CERTIFICATE
            socket_object = ssl.wrap_socket(socket_object, keyfile=self.key_file, certfile=self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1_2)
            #print("Socket created successfully ...")
            return socket_object
        except socket.error as error:
            print("Socket creation failed with error code: '{0}'".format(error))

    # Handles binding port/host and listening -> initiates handleconnections
    def startServer(self):
        try:
            self.server_socket.bind((self.host,self.port))
        except socket.error as e:
            print(str(e))
        print("Server is listening on port {0}".format(self.port))
        self.server_socket.listen()
        while True:
            self.handleConnections()

    def handleReceivingContacts(self, data):
        # unpickle user login data
        pickle_object = pickle.loads(data)
        # add the user to the list of logged in users
        self.logged_in_users.append(pickle_object)

    def handleUpdateContacts(self, data):
        # unpickle user login data
        pickle_object = pickle.loads(data)
        for user in self.logged_in_users:
            if user.name == pickle_object.name and user.email == pickle_object.email:
                user.contacts = pickle_object.contacts
                return

    # Check passed contact list from user against online contacts
    def checkOnlineUser(self, data):
        pickle_object = pickle.loads(data)
        online_users = "The following contacts are online:"
        target = None
        for user in self.logged_in_users:
            if user.name == pickle_object.name and user.email == pickle_object.email:
                target = user
                break
        if target is None:
            print("Error: Could not find target user with data " + pickle_object)
            return
        for contact in target.contacts:
            name = util.Decrypt(contact.name, target.password, target.salt)
            email = util.Decrypt(contact.email, target.password, target.salt)
            if self.isUserLoggedIn(name,email):
                online_users += "\n* {0} <{1}>".format(name, email)
        return online_users.encode()

    # removes a user from the logged in users list
    # this assumes that only one user with the given name and email exists at a time
    def handleLogout(self, data):
        pickle_object = pickle.loads(data)
        for user in self.logged_in_users:
            if user.name == pickle_object.name and user.email == pickle_object.email:
                self.logged_in_users.remove(user)
                return

    # checks if the a user with the given name and email is logged in/online
    def isUserLoggedIn(self, name, email):
        return any(x.name == name and x.email == email for x in self.logged_in_users)
        # Debugging - Alex
        # for user in self.logged_in_users:
        #     print("Currently checking -> {0} , {1}\n {2} , {3}".format(name,email,user.name,user.email))
        #     if user.name == name and user.email == email:
        #         print("equal")
        #         return True

    # USE THIS to handle incoming requests to the server
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
                self.handleReceivingContacts(data)
            elif message == "UPDATE CONTACTS":
                data = connection.recv(2048)
                self.handleUpdateContacts(data)
            elif message == "LIST USERS":
                # Check if users are online from users contact, send them user object
                data = connection.recv(2048)
                connection.send(self.checkOnlineUser(data))
            elif message == "SHUTDOWN":
                print("Shutting Down Server ...")
                connection.sendall("Shutdown Initiated. Goodbye!".encode())
                connection.close()
                # Unclean
                os._exit(1)
            # I just have it sending back what the client sent, change to whatever you want to send back
            # reply = "Server: {0}".format(message)
            # connection.sendall(reply.encode())

    # Multithreading
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

# For combining contacts and User ^ could combine if you wanted to, would require some changing
class ServerUser:
    def __init__(self, name, email, contacts, password, salt):
        self.name = name
        self.email = email
        self.contacts = contacts
        self.password = password
        self.salt = salt

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

    # Send class with name, email, contacts to server
    def sendObjectToServer(self):
        data = json.loads(open("user.json", "r").read())
        temp = ServerUser(self.local_user.name,self.local_user.email,self.contacts, data["password"], data["salt"])
        temp_pickle_string = pickle.dumps(temp)
        self.client_socket.send(temp_pickle_string)

    # Send only our name and email when we log out
    def sendLogoutToServer(self):
        temp_pickle_string = pickle.dumps(self.local_user)
        self.client_socket.send("EXIT".encode())
        self.client_socket.send(temp_pickle_string)

    # creates a new user if one doesnt exist
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

    # loads the user data from the filesystem
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
                print('Email and Password Combination Invalid.')
            else:
                break
        # dont store the users password in this object, as it isnt needed anymore
        return User(data["name"], data["email"])

    # loads the user's contacts from the filesystem
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

    # saves the user's contacts to the filesystem
    def saveContacts(self):
        with open('contacts.json', 'w') as output:
            output.write(json.dumps([x.__dict__ for x in self.contacts]))
        self.client_socket.send("UPDATE CONTACTS".encode())
        self.sendObjectToServer()

    # handles adding a new contact to the user's contact list
    def handleAdd(self):
        name = input('Enter Full Name: ')
        email = input('Enter Email Address: ')
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
        print('Contact Added.')
        self.saveContacts()
    
    # handles listing the user's contacts
    def handleList(self):
        self.client_socket.send("LIST USERS".encode())
        # Debugging - Alex
        # print(self.contacts[0].name)
        pickle_message = pickle.dumps(self.local_user)
        self.client_socket.send(pickle_message)
        response = self.client_socket.recv(2048)
        print(response.decode())

    # Creates SSL socket
    def createSSLSocket(self):
        try:
            socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # the SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire.
            socket_object.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Wrap in ssl with our cert and using TLS v1.2 or Greater
            socket_object = ssl.wrap_socket(socket_object, keyfile=self.key_file, certfile=self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1_2)
            print("Socket created successfully ...")
            return socket_object
        except socket.error as error:
            print("Socket creation failed with error code: '{0}'".format(error))

    # Initiates connection and starts UI
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
        while True:
            self.handleUI()

    # This is where to handle options / adding file functionality etc -----
    # TODO: remove debug response.decode() statements
    def handleUI(self):
        #choice = input("1. Input message to send\n2. Send file\n8. Exit server\n9. Send Shutdown Message to Server\nChoose option: ")
        data = input("secure_drop> ").lower().split(' ');
        choice = data[0]
        args = data[1:]
        if choice == "help":
            print('  "add" -> Add a new contact')
            print('  "list" -> List all online contacts')
            print('  "send" -> Transfer file to contact')
            print('  "exit" -> Exit SecureDrop')
            print('  "shutdown" -> DEBUG COMMAND. Shuts down the server')
        elif choice == "exit":
            self.sendLogoutToServer()
            self.client_socket.close()
            exit()
        elif choice == "shutdown":
            self.client_socket.send("SHUTDOWN".encode())
            response = self.client_socket.recv(2048)
            print(response.decode())
            print("Exiting... Goodbye :)")
            try:
                self.client_socket.close()
            except socket.error as e:
                print(str(e))
            exit()
        elif choice == "add":
            self.handleAdd()
        elif choice == "list":
            self.handleList()
        # TODO: make this require a contact and path parameter
        # as per the requirements
        elif choice == "send":
            file_path = input("Enter filepath: ")
            with open(file_path, "r") as read_file:
                temp = read_file.read()
            self.client_socket.send(temp.encode())
            response = self.client_socket.recv(2048)
            print(response.decode())
        else:
            print('Unknown command.\nType "help" for commands.\n')
            
