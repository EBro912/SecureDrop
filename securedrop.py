# TODO: handle user account creation and loading (if one exists) here

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