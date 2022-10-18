# TODO: handle user account creation and loading

print('Welcome to SecureDrop.\nType "help" for commands.\n')

def handleHelp():
    print('\t"add" -> Add a new contact')
    print('\t"list" -> List all online contacts')
    print('\t"send" -> Transfer file to contact')
    print('\t"exit" -> Exit SecureDrop')

def handleAdd():
    print("TODO")

def handleList():
    print("TODO")

def handleSend():
    print("TODO")

while True:
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