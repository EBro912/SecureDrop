import socket
import ssl

# AF_INET = IPv4
# SOCK_STREAM = TCP

# Important, for creating certificates we can use openssl

# Check if you have openssl
# openssl version

# If you need a private key, run
    # openssl genrsa -out key.pem 2048

# For a password protected one
    # openssl genrsa -aes256 -out key.pem 2048

# To generate a certificate from the private key
    # openssl req -new -key key.pem -out signreq.csr

# To sign the certificate with the private key
    # openssl x509 -req -days 365 -in signreq.csr -signkey key.pem -out certificate.pem

# To view certificate details
    # openssl x509 -text -noout -in certificate.pem



# Simplified Funcitonality for both

# Server Side
    # Create a server object
        # server = serverObject()
    # If you need specific port / key location / certificate location go into clientObject and change the self.key_file , self.cert_file and self.connect_to_port respectively for what you need
    # After configuring, to start server simply run
        # server.startServer()

# Client side
    # Create a client object
        # client = clientObject()
    # If you need specific port / key location / certificate location go into clientObject and change the self.key_file , self.cert_file and self.connect_to_port respectively for what you need
    # After configuring, to connect to server simply run
        # client.connectToServer()

        
class testUser():
    def __init__(self):
        self.name = "alex"
        self.password = "123"

test_user = testUser()

class clientObject():
    def __init__(self, port=52484):
        self.connect_to_port = port
        self.host_ip = "127.0.0.1"
        self.key_file = "keys/key.pem"
        self.cert_file = "keys/certificate.pem"
        self.client_socket = self.create_socket_object()

    def create_socket_object(self):
        try:
            socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # the SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire.
            socket_object.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Wrap in ssl with our cert and private key , THIS ONLY WORKS WITH THE KEY YOU USED TO CREATE THE CERTIFICATE
            socket_object = ssl.wrap_socket(socket_object, keyfile=self.key_file, certfile=self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1_2)
            print("Socket created successfully ...")
            return socket_object
        except socket.error as error:
            print("Socket creation failed with error code: '{0}'".format(error))

    def closeConnection(self):
        self.client_socket.close()

    """
    def connectToServer(self, host_ip):
         print("Connecting to: '{0}'".format(host_ip))
         self.client_socket.connect((host_ip,self.connect_to_port))
         print("Socket connected to '{0}' successfully".format(host_ip))
         print("Receiving data from the server ... ...")
         print(self.client_socket.recv(1024).decode())
    """

    # Since we are on local machine, im just going to hardcode the loopback interface to simplify input
    def sendDataToServer(self, data):
        try:
            print("Connecting to: '{0}'".format(self.host_ip))
            self.client_socket.connect((self.host_ip,self.connect_to_port))
            print("Socket connected to '{0}' successfully".format(self.host_ip))
            self.client_socket.sendall(data.encode("utf-8"))
            # Wait for response
            print(self.client_socket.recv(1024).decode())
        except socket.error as error:
            print("Socket creation failed with error code: '{0}'".format(error))

class serverObject():
    def __init__(self, port=52484):
        self.listening_port = port
        self.server_running = True
        self.cert_file = "keys/certificate.pem"
        self.key_file = "keys/key.pem"
        self.server_socket = self.create_socket_object()

    # Auto calls
    def create_socket_object(self):
        try:
            socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # the SO_REUSEADDR flag tells the kernel to reuse a local socket in TIME_WAIT state, without waiting for its natural timeout to expire.
            socket_object.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Wrap in ssl with our cert and using TLS v1.2 or Greater
            socket_object = ssl.wrap_socket(socket_object, server_side=True,keyfile=self.key_file, certfile=self.cert_file, ssl_version=ssl.PROTOCOL_TLSv1_2)
            print("Socket created successfully ...")
            return socket_object
        except socket.error as error:
            print("Socket creation failed with error code: '{0}'".format(error))

    """    
    def startServer(self):
        self.server_socket.bind(('127.0.0.1',self.listening_port))
        print("Socket successfully binded to port '{0}'".format(self.listening_port))
        # .listen(5) -> 5 sockets are kept waiting, if a 6th tries to connect it is dropped / denied
        self.server_socket.listen(5)
        print("Socket is now listening for all incoming requests")
        while self.server_running:
            conn, addr = self.server_socket.accept()
            print("'{0}' connected".format(addr))
            conn.send("Welcome to Nexus!".encode())
            conn.close()
            self.server_running = False
    """
    def listenServer(self):
        self.server_socket.bind(('127.0.0.1',self.listening_port))
        print("Socket successfully binded to port '{0}'".format(self.listening_port))
        # .listen(5) -> 5 sockets are kept waiting, if a 6th tries to connect it is dropped / denied
        self.server_socket.listen(5)
        while self.server_running:
            connection, client_address = self.server_socket.accept()
            print("Connection established with '{0}'".format(client_address))
            data = connection.recv(1024)
            print(f"Received: {data.decode('utf-8')}")
            # Here
            send_back = self.handleRequests(data.decode('utf-8'))
            # Only if received end session message
            if not send_back:
                self.server_running = False
                break
            # otherwise send back data
            connection.send(send_back.encode())
            # Close each session at end, but loop keeps listening for more
            connection.close()


    def handleRequests(self, request):
        if request == "get users":
            return test_user.name
        elif request == "end session":
            return False
        else:
            return "Invalid Request"