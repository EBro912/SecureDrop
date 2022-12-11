# from socketFunctionality import serverObject


# server = serverObject()
# server.listenServer()

from multiThreadedSockets import serverSide

server = serverSide()
server.startServer()