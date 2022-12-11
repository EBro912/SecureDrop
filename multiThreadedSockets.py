import socket
import os
from _thread import *
import ssl

class serverSide():
    # If the filepath changes, or you wnat to change port/ host etc
    def __init__(self):
        self.host = '127.0.0.1'
        self.port = 52000
        self.key_file = "keys/key.pem"
        self.cert_file = "keys/certificate.pem"
        self.server_socket = self.createSSLSocket()

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

    # USE THIS to handle incoming requests to the server
    def handleClient(self,connection):
        connection.send("Welcome to the server".encode())
        while True:
            data = connection.recv(2048)
            message = data.decode('utf-8')
            if message == "EXIT":
                break
            elif message == "SHUTDOWN":
                print("Shutting Down Server ...")
                connection.sendall("Shutdown Initiated. Goodbye!".encode())
                connection.close()
                # Unclean exit but quick...
                os._exit(1)
            # I just have it sending back what the client sent, change to whatever you want to send back
            reply = "Server: {0}".format(message)
            connection.sendall(reply.encode())
        connection.close()

    # Multithreading
    def handleConnections(self):
        client, address = self.server_socket.accept()
        print("Connected to: {0}:{1}".format(address[0],str(address[1])))
        start_new_thread(self.handleClient, (client, ))


# Client side
class clientSide():
    def __init__(self):
        self.connect_to_host = '127.0.0.1'
        self.connect_to_port = 52000
        self.cert_file = "keys/certificate.pem"
        self.key_file = "keys/key.pem"
        self.client_socket = self.createSSLSocket()

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
        try:
            self.client_socket.connect((self.connect_to_host,self.connect_to_port))
        except socket.error as e:
            print(str(e))
        response = self.client_socket.recv(2048)
        print(response.decode())
        while True:
            self.handleUI()

    # This is where to handle options / adding file functionality etc -----
    def handleUI(self):
        while True:
            choice = input("1. Input message to send\n2. Send file\n8. Exit server\n9. Send Shutdown Message to Server\nChoose option: ")
            if choice == "1":
                message = input("Please enter message to send: ")
                self.client_socket.send(message.encode())
                response = self.client_socket.recv(2048)
                print(response.decode())
            elif choice == "2":
                file_path = input("Enter filepath: ")
                with open(file_path, "r") as read_file:
                    temp = read_file.read()
                self.client_socket.send(temp.encode())
                response = self.client_socket.recv(2048)
                print(response.decode())
            elif choice == "8":
                self.client_socket.send("EXIT".encode())
                response = self.client_socket.recv(2048)
                print(response.decode())
                print("Exiting... Goodbye :)")
                self.client_socket.close()
                exit()
            elif choice == "9":
                self.client_socket.send("SHUTDOWN".encode())
                response = self.client_socket.recv(2048)
                print(response.decode())
                print("Exiting... Goodbye :)")
                try:
                    self.client_socket.close()
                except socket.error as e:
                    print(str(e))
                exit()
            else:
                print("Error deciding option. Try again")
