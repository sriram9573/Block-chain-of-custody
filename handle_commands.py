import os
import blockchain_implement
import datetime
import time

class bchoc:
    path = ""
    aes_key = str("R0chLi4uLi4uLi4=").encode('utf-8').ljust(16, b'\0')
    arguments = []

    acceptableReasons = ["DISPOSED", "DESTROYED", "RELEASED"]
    acceptableOwners = ["POLICE", "LAWYER", "ANALYST", "EXECUTIVE"]
    bchocPasswords = {}

    bchocFileExists = False
    
    def __init__(self, argv):
        if('BCHOC_FILE_PATH' in os.environ):
          self.path = os.environ['BCHOC_FILE_PATH']   # provided path
         # self.path = '/Users/sriramreddy/Desktop/cse469/block.txt'
        else:
            self.path = os.getcwd() + "/bchoc.dat"  # raw binary file

        self._init_pass_dict();

        # save arguments
        self.arguments = argv
                
        # Parse commands and execute them
        self.chain = blockchain_implement.Chain(self.path, self.aes_key)
        self._parse_cmds()


    def _init_pass_dict(self):
        self.bchocPasswords[self._getEnvValue('BCHOC_PASSWORD_POLICE')] = 'POLICE'
        self.bchocPasswords[self._getEnvValue('BCHOC_PASSWORD_LAWYER')] = 'LAWYER'
        self.bchocPasswords[self._getEnvValue('BCHOC_PASSWORD_ANALYST')] = 'ANALYST'
        self.bchocPasswords[self._getEnvValue('BCHOC_PASSWORD_EXECUTIVE')] = 'EXECUTIVE'
        self.bchocPasswords[self._getEnvValue('BCHOC_PASSWORD_CREATOR')] = 'CREATOR'

    def _getEnvValue(self, envName):
        if (envName in os.environ):
            return os.environ[envName]
        else:
            return ''
    

    def getNextArg(self):
        # Try to pop, and throw the error if it does not work
        try:
            return self.arguments.pop(0)
        except (IndexError):
            print("Error: Incorrect number of arguments")
            exit(1)

    def peekNextArg(self):
        # Check that there are still arguments remaining
        if (len(self.arguments) > 0):
            return self.arguments[0]
        # If there are none, return the end of argument string
        else:
            return "END_OF_ARGUMENT"

    def expectArg(self, expectVal):
        # Get the next argument
        nextArg = self.peekNextArg()
        
        # If it does not match with expected, throw an error
        if (nextArg != expectVal):
            print(f"Unexpected command line argument: {nextArg} instead of {expectVal}")
            exit(1)
        elif (len(self.arguments) > 0):
            self.getNextArg()

    def _parse_cmds(self):
        # Get the operation
        operation = self.getNextArg()

        # No blockchain file exits, create one and note creation NOTE: MAY REQUIRE REPAIR
        if not os.path.isfile(self.path):
            initblock = blockchain_implement.Block(0, 'Initial', 'Initial Block', self.aes_key)
            initblock.init_file(self.path)
        else:
            self.bchocFileExists = True

        # Follow the path matching the command, throwing an error if there is no match
        if operation == "add":
            self._parse_add()
        elif operation == "checkin":
            self._parse_checkin()
        elif operation == "checkout":
            self._parse_checkout()
        elif operation == "show":
            self._parse_show()
        elif operation == "remove":
            self._parse_remove()
        elif operation == "init":
            # Verify it has ended
            self.expectArg("END_OF_ARGUMENT")
            self.initOutput()
        elif operation == "verify":
            # Verify it has ended
            self.expectArg("END_OF_ARGUMENT")  
            self.verify()
        else:
            print("Invalid command")
            exit(1)
            

    def _parse_add(self):
        # Grab the case id
        self.expectArg("-c")
        case_id = self.getNextArg()

        # Get all item ids
        item_ids = []
        moreItems = True
        while(moreItems):
            self.expectArg("-i")
            newID = self.getNextArg()

            item_ids.append(newID)

            tempArg = self.peekNextArg()
            moreItems = tempArg == "-i"
            
        # Get creator
        self.expectArg("-g")
        creator = self.getNextArg()

        # Get password
        self.expectArg("-p")
        password = self.getNextArg()
        
        # Verify it has ended
        self.expectArg("END_OF_ARGUMENT")

        self.add(case_id, item_ids, creator, password)

    def _parse_show(self):
        # Get the show type
        showType = self.getNextArg()

        # Follow the path aligning with the found type
        if showType == "cases":
            self._parse_show_cases()
        elif showType == "items":
            self._parse_show_items()
        elif showType == "history":
            self._parse_show_history()
        else:
            print("Incorrect show type (Expects: 'cases', 'items', or 'history')")
            exit(1)

    def _parse_checkin(self):
        # Get the item's id
        self.expectArg("-i")
        itemId = self.getNextArg()
    
        # Get the password
        self.expectArg("-p")
        password = self.getNextArg()

        # Verify it has ended
        self.expectArg("END_OF_ARGUMENT")

        self.checkin(itemId, password)
    
    def _parse_checkout(self):
        # Get the item's id
        self.expectArg("-i")
        itemId = self.getNextArg()
    
        # Get the password
        self.expectArg("-p")
        password = self.getNextArg()

        # Verify it has ended
        self.expectArg("END_OF_ARGUMENT")

        self.checkout(itemId, password)

    def _parse_remove(self):
        # Get the item's id
        self.expectArg("-i")
        itemId = self.getNextArg()
    
        # Get the reason
        whyForm = self.peekNextArg()
        if (whyForm == "-y"):
            self.expectArg("-y")
        else:
            self.expectArg("--why")
        
        reason = self.getNextArg().upper() # NOTE: the conversion to uppercase
        self.verifyReason(reason)

        # Get the password
        self.expectArg("-p")
        password = self.getNextArg()

        # Verify it has ended
        self.expectArg("END_OF_ARGUMENT")

        self.remove(itemId, reason, password)

    def verifyReason(self, reason):
        # Check for any match, returning if found
        for acceptReason in self.acceptableReasons:
            if (reason == acceptReason):
                return

        # Throw an error if no match is found
        print("Invalid reason (Expects: DISPOSED, DESTROYED, or RELEASED)")
        exit(1)

    def verifyOwner(self, owner):
        # Check for any match, returing if found
        for acceptOwner in self.acceptableOwners:
            if (owner == acceptOwner):
                return
        
        # Throw an error if no match is found
        print("Invalid owner (Expects: POLICE, LAWYER, ANALYST, or EXECUTIVE)")
        exit(1)

    def _parse_show_cases(self):
        # Verify it has ended
        self.expectArg("END_OF_ARGUMENT")

        self.show_cases()
    
    def _parse_show_items(self):
        # Get the case-id
        self.expectArg("-c")
        caseID = self.getNextArg()

        # Verify it has ended
        self.expectArg("END_OF_ARGUMENT")

        self.show_items(caseID)


    def _parse_show_history(self):
        caseID = ""
        itemID = ""
        numEntries = ""
        isReversed = False
        password = ""

        # Check for caseID, saving if there
        tempArg = self.peekNextArg()
        if (tempArg == "-c"):
            self.expectArg("-c")
            caseID = self.getNextArg()
        
        # Check for itemID, saving if there 
        tempArg = self.peekNextArg()
        if (tempArg == "-i"):
            self.expectArg("-i")
            itemID = self.getNextArg()
        
        # Check for a number of entries, saving if there
        tempArg = self.peekNextArg()
        if (tempArg == "-n"):
            self.expectArg("-n")
            numEntries = self.getNextArg()

        # Check if reverse is requested
        tempArg = self.peekNextArg()
        if (tempArg == "-r"):
            self.expectArg("-r")
            isReversed = True
        elif (tempArg == "--reverse"):
            self.expectArg("--reverse")
            isReversed = True

        # Check for a password, saving if there
        tempArg = self.peekNextArg()
        if (tempArg == "-p"):
            self.expectArg("-p")
            password = self.getNextArg()

        # Verify it has ended
        self.expectArg("END_OF_ARGUMENT")

        self.show_history(caseID, itemID, numEntries, isReversed, password)


    def add(self, case_id, item_ids, creator, password):
        # Check that the password is a creator password
        if (not self.checkCreatorPassword(password)):
            print('ERROR: Incorrect Creator Password')
            exit(1)
        
        # Check that each item id does not exist in the chain
        for item_id in item_ids:
            if(self.chain.get_item_id(item_id) != -1):   
                print("Error: Item ID [" + str(item_id) + "] already exists in the blockchain")
                exit(1)
        
        data = ""
        
        # Place each item on the chain
        for item_id in item_ids:
            newBlock = blockchain_implement.Block(self.chain.get_last_block_hash(), "CHECKEDIN", data, self.aes_key, case_id, item_id, creator, owner=None)
            newBlock.write_block(self.path)

            print(f"Item: {item_id}")
            print(f"Action: CHECKEDIN")
            print(f'Time of Action: {datetime.datetime.fromtimestamp(newBlock.timestamp).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}')
            print()

    def checkin(self, item_id, password):
        # Get the user associated with the password given
        owner = self.checkPassword(password)
        
        # Obtain the location of the target evidence within the file
        indexOfEvidence = self.chain.get_item_id(item_id)

        # If the evidence was not found, throw an error
        if(indexOfEvidence == -1):   
            print("Error: Cannot Check In [" + str(item_id) + "]. Item ID does not exist in the blockchain")
            exit(1)
        # If the evidence is already checked in, throw an error
        if(self.chain.is_checkedIn(indexOfEvidence)):
            print("Error: Cannot Check In [" + str(item_id) + "]. Item ID is already checked in")
            exit(1)
        # If the evidence has been removed, throw an error
        if (not self.chain.is_checkedOut(indexOfEvidence)):
            print("Error: Cannot Check In [" + str(item_id) + "]. Item ID is removed")
            exit(1)

        # Check the data in, saving the case id
        caseID = self.chain.checkin(indexOfEvidence, owner)

        # Print the results
        print(f"Case: {caseID}")
        print(f"Checked in item: {item_id}")
        print(f"Status: CHECKEDIN")
        print(f'Time of Action: {datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}')

    def checkout(self, item_id, password):
        # Get the user associated with the password given
        owner = self.checkPassword(password)
        
        # Obtain the location of the target evidence within the file
        indexOfEvidence = self.chain.get_item_id(item_id)

        # If the evidence was not found, throw an error
        if(indexOfEvidence == -1):
            print("Error: Cannot Check out [" + str(item_id) + "]. Item ID does not exist in the blockchain")
            exit(1)
        # If the evidence is already checked out, throw an error
        if(self.chain.is_checkedOut(indexOfEvidence)):
            print("Error: Cannot Check out [" + str(item_id) + "]. Item ID is already checked out")
            exit(1)
        # If the evidence has been removed, throw an error
        if (not self.chain.is_checkedIn(indexOfEvidence)):
            print("Error: Cannot Check out [" + str(item_id) + "]. Item ID is removed")
            exit(1)
        
        # Checkout the evidence
        caseID = self.chain.checkout(indexOfEvidence, owner)
        
        # Print the results
        print(f"Case: {caseID}")
        print(f"Checked in item: {item_id}")
        print(f"Status: CHECKEDOUT")
        print(f'Time of Action: {datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}')
        
    def show_cases(self):
        # Obtain all cases
        cases = self.chain.get_cases()

        # Loop over all cases, printing
        for case in cases:
            print(case)
        
    def show_items(self, caseID):
        # Obtain all items
        items = self.chain.get_items(caseID)

        # Loop over all items, printing
        for item in items:
            print(item)
    
    def show_history(self, caseID, itemID, numEntries, isReversed, password):
        # If the password exists, grab the associated user
        if (password != ""):
            owner = self.checkPassword(password)
        # Otherwise dont set an associated user
        else:
            owner = ""

        # Obtain the history-- NOTE: returns a tuple, (caseID, itemID, state, timestamp)
        history = self.chain.get_history(caseID, itemID, numEntries, isReversed, owner)

        # Print every moment in the history 
        for moment in history:
            print(moment[0] + '\n' + moment[1]+ '\n' + moment[2]+ '\n' + moment[3] + '\n')
        
    def remove(self, item_id, reason, password):
        # Throw an error if the password is not a creator password
        if (not self.checkCreatorPassword(password)):
            print('ERROR: Incorrect Creator Password')
            exit(1)

        # Obtain the location of the evidence within the file
        indexOfEvidence = self.chain.get_item_id(item_id)
        
        # reason is one of DISPOSED, DESTROYED, RELEASED

        # If the evidence was not found, throw an error
        if(indexOfEvidence == -1):   
            print("Error: Cannot remove " + str(item_id) + ". Item ID does not exist in the blockchain")
            exit(1)
        # If the evidence is checkedout or already removed, throw an error
        elif (not self.chain.is_checkedIn(indexOfEvidence)):
            print("Error: Cannot remove " + str(item_id) + ". Item is not checked in")
            exit(1)
        # Otherwise add a remove block to the chain
        else:
            self.chain.remove(indexOfEvidence, reason)

            print(f"Removed Item: {item_id}")
            print(f"Status: {reason}")
            print(f'Time of action: {datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}')

    def initOutput(self):
        # Verify that the file was found earlier, noting its creation if one had to be made
        if (self.bchocFileExists):
            print("Blockchain file found with INITIAL block.")
        else:
            print("Blockchain file not found. Created INITIAL block.")
        
        # Verify the files contents--throw an error if invalid
        if (self.chain.verify() == ""):
            print("Blockchain file validated")
        else:
            print("ERROR: Blockchain file invalid")
            exit(1)

    def verify(self):
        # Set the default state
        state = "CLEAN"

        # Determine if a bad block exists, finding the first location
        badblockResponseString = self.chain.verify()
        if badblockResponseString != "":
            state = "ERROR"

        print("Transactions in blockchain: " + str(self.chain.get_blockcount()))
        print("State of blockchain: " + state)

        # If a bad block was found, throw an error
        if badblockResponseString:
            print(badblockResponseString)
            exit(1)
        
    
    def checkCreatorPassword(self, password):
        if (password in self.bchocPasswords and self.bchocPasswords[password] == 'CREATOR'):
            return True
        else:
            return False
    
    def checkPassword(self, password):
        if (password in self.bchocPasswords):
            return self.bchocPasswords[password]
        # If no users are associated with the password, throw an error
        else:
            print("Error--Invalid Password")
            exit(1)
