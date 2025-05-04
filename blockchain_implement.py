import hashlib
import time
import datetime
import struct
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import uuid

def encrypt_evidence_id(evidence, key):
    cipher = AES.new(key, AES.MODE_ECB)
    dataBytes = int.to_bytes(int(evidence.encode()), 4, 'big')
    return cipher.encrypt(b'\x00' * 12 + dataBytes)

def encrypt_uuid(targetUUID, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(uuid.UUID(targetUUID).bytes)

def decrypt_uuid(encryptedUUID, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return uuid.UUID(int=int.from_bytes(cipher.decrypt(encryptedUUID), 'big'))

def decrypt_evidence_id(encryptedEvidence, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return int.from_bytes(cipher.decrypt(encryptedEvidence), 'big')

class Block:
    def __init__(self, previous_hash, state, data, aes_key, case_id=None, evidence_item_id=None,  creator=None, owner=None, rawBytes=False):
        self.rawBytes = rawBytes
        if not rawBytes:
            self.aes_key = aes_key
            self.previous_hash = previous_hash
            self.timestamp = time.time()
            self.case_id = case_id if case_id else bytes(0)
            self.evidence_item_id = evidence_item_id if evidence_item_id else bytes(0)
            self.state = state.encode('utf-8')
            self.creator = creator[:12].encode('utf-8') if creator else bytes(0)
            self.owner = owner.encode('utf-8') if owner in ['Police', 'Lawyer', 'Analyst', 'Executive'] else bytes(0)
            self.data = data
            self.data_length = len(data.encode('utf-8'))
        else:
            self.aes_key = aes_key
            self.previous_hash = previous_hash
            self.timestamp = time.time()
            self.case_id = case_id
            self.evidence_item_id = evidence_item_id
            self.state = state
            self.creator = creator
            self.owner = owner
            self.data = data
            self.data_length = len(data)
       
    def write_block(self, path):
        if not self.rawBytes:
            if self.case_id:
                self.case_id = encrypt_uuid(self.case_id, self.aes_key)
            if self.evidence_item_id:
                self.evidence_item_id = encrypt_evidence_id(self.evidence_item_id, self.aes_key)

        with open(path, 'ab') as file:
            file.write(struct.pack("32s d 32s 32s 12s 12s 12s I", self.previous_hash,
                       self.timestamp, self.case_id.hex().encode(), self.evidence_item_id.hex().encode(),
                       self.state, self.creator, self.owner, self.data_length))

            if(self.rawBytes):
                file.write(self.data)
            else:
                file.write(self.data.encode('utf-8'))
    
    def init_file(self, path):
        with open(path, 'wb') as file:
            file.write(struct.pack("32s 8s 32s 32s 12s 12s 12s I", b'\x00' * 32, b'\x00' * 8, b'0' * 32, b'0' * 32, b'INITIAL\0\0\0\0\0', b'\x00'*12, b'\x00' * 12, 14))
            file.write(b'Initial block\0')

    
class Chain:
    def __init__(self, path, aes_key):
        self.chunk_mem = 1024
        self.path = path
        self.aes_key = aes_key
        self.currItemState = dict()
        self.savedPreviousBlocks = list()
        self.allBlocks = list()
    
      
    def verify(self):
        badBlockReasoning = ""

        # Open the file
        with open(self.path, 'rb') as f:
            actual_prev_hash = b'\x00' * 32 
            count = 0

            while True:
                count += 1

                block = f.read(0x90)

                if not block:
                    break
                
                itemID = block[0x48:0x68]
                state = block[0x68:0x74].strip(b'\x00').decode('utf-8')

                previous_hash = block[0x00:0x20]
                dataLength = block[0x8c:0x90]
                targetData = f.read(int.from_bytes(dataLength, 'little'))
                
                validPreviousHash = previous_hash == actual_prev_hash

                # Get the hash value of the current block
                actual_prev_hash = hashlib.sha256(block + targetData).digest()

                # Check for a duplicate block
                duplicateBlock = self.duplicateBlockCheck(hashlib.sha256(block + targetData).digest())
                if (duplicateBlock):
                    badBlockReasoning = f"Bad block: {actual_prev_hash.hex()}\nTwo duplicate blocks were found"
                    break

                # Check for a duplicate parent block
                duplicateParent = self.duplicateParentCheck(previous_hash)
                if (duplicateParent):
                    badBlockReasoning = f"Bad block: {actual_prev_hash.hex()}\nTwo blocks were found with the same parent"
                    break

                # Verify the transition in state
                invalidTransitionString = self.validTransitionCheck(itemID, state, count)
                if (invalidTransitionString != None):
                    badBlockReasoning = f"Bad block: {actual_prev_hash.hex()}\n{invalidTransitionString}"
                    break

                # Verify the hash values
                if (not validPreviousHash):
                    badBlockReasoning = f"Bad block: {actual_prev_hash.hex()}\nBlock Contents do not match block checksum"
                    break

        return badBlockReasoning
    
    def duplicateBlockCheck(self, blockHash):
        if blockHash in self.allBlocks:
            return True
        else:
            self.allBlocks.append(blockHash)
            return False

    def duplicateParentCheck(self, parent_hash):
        if (parent_hash in self.savedPreviousBlocks):
            return True
        else:
            self.savedPreviousBlocks.append(parent_hash)
            return False
    
    def validTransitionCheck(self, itemID, state, count):
        if (itemID in self.currItemState):
            stateTransitionString = self.validStateTransition(self.currItemState[itemID], state)
            if (stateTransitionString != None):
                return stateTransitionString
            else:
                self.currItemState[itemID] = state
        else:
            if ((state == 'INITIAL' and count != 1)):
                return "Item state set to initial"
            elif (state != "CHECKEDIN" and count != 1):
                return "Item was not checked in first"
            # Otherwise add the block, as it is valid
            else:
                self.currItemState[itemID] = state

        return None

    def validStateTransition(self, originalState, newState):    
        if (originalState == 'CHECKEDIN' and newState == 'CHECKEDIN'):
            return "Item Checked in after being checked in"
        elif (originalState == 'CHECKEDOUT' and newState == 'CHECKEDOUT'):
            return "Item Checked out after being checked out"
        elif (originalState == 'CHECKEDOUT' and self.removeStateCheck(newState)):
            return "Item removed after being checked out"
        elif (self.removeStateCheck(originalState) and self.removeStateCheck(newState)):
            return "Item was removed after being removed"
        elif (self.removeStateCheck(originalState)):
            return "Item was checked out or checked in after removal from chain"
        else:
            return None

    def removeStateCheck(self, targetState):
        return targetState == 'DISPOSED' or targetState == 'DESTROYED' or targetState == 'RELEASED'
    
    def get_last_block_hash(self):
        block = b''
        data = b''
        hash_digest = b''

        with open(self.path, 'rb') as f:
            # iterate through the file to find the last block
            while True:
                block = f.read(0x90)
                
                if (not block):
                    break
                
                data_length = block[0x8c : 0x90]
                data = f.read(int.from_bytes(data_length, 'little'))

                hash_digest = hashlib.sha256(block + data).digest()
        
        # Return the hash of the last saved block
        return hash_digest

    def get_item_id(self, item_id):
        currIndex = 0
        indexOfTarget = -1

        with open(self.path, 'rb') as f:
            # iterate through the file to find the last block
            while True:
                block = f.read(0x90)
                
                if (not block):
                    break

                # Grab the state and item_id of the block
                aes_evidence_item_id = bytes.fromhex(block[0x48:0x68].decode('utf-8'))
                state = block[0x68: 0x74]
                dataLength = block[0x8c: 0x90]

                # Save the index if it matches the given item_id
                if not state.strip(b'\x00').decode('utf-8') == 'INITIAL':
                    if decrypt_evidence_id(aes_evidence_item_id, self.aes_key) == int(item_id):
                        indexOfTarget = currIndex

                # Move the file pointer forward
                f.seek(int.from_bytes(dataLength, 'little'), 1)

                # Move the current index forwards
                currIndex += 0x90 + int.from_bytes(dataLength, 'little')

        # Return the found index of the item id, -1 if not found
        return indexOfTarget

    def is_checkedIn(self, locationOfItem):
        checkedIn = False

        # Open the file
        with open(self.path, 'rb') as f:
            # Find the block
            f.seek(locationOfItem, 0)

            # Get the state
            block = f.read(0x90)
            state = block[0x68 : 0x74]

            # Determine if it is CHECKEDIN
            checkedIn = state.strip(b'\x00').decode('utf-8') == "CHECKEDIN"

        # Return the result
        return checkedIn
    
    def is_checkedOut(self, locationOfItem):
        checkedOut = False
        
        # Open the file
        with open(self.path, 'rb') as f:
            # Find the block
            f.seek(locationOfItem, 0)

            # Get the state
            block = f.read(0x90)
            state = block[0x68 : 0x74]

            # Determine if it is CHECKEDOUT
            checkedOut = state.strip(b'\x00').decode('utf-8') == "CHECKEDOUT"
        
        # Return the result
        return checkedOut

    def get_blockcount(self):
        # Open the file
        with open(self.path, 'rb') as f:
            count = 0

            # Iterate over all blocks
            while True:
                # Get the block, stopping if no more
                block = f.read(0x90)
                if (not block):
                    break

                # Skip the data
                dataLength = block[0x8c: 0x90]
                f.seek(int.from_bytes(dataLength, 'little'), 1)
                
                # Iterate count
                count += 1

        # Return count
        return count
    

    def checkin(self, indexOfEvidence, owner):
        target_owner = b''
        target_case_id = b''
        target_evidence_item_id = b''
        target_creator = b''
        dataLength = b''
        target_data = b''

        # Open the file
        with open(self.path, 'rb') as f:
            # Jump to the target block, saving
            f.seek(indexOfEvidence)
            block = f.read(0x90)

            # Set the new block's owner, case_id, item_id, and creator using the original block
            target_owner = owner.encode() + (12 - len(owner)) * b'\x00'
            target_case_id = bytes.fromhex(block[0x28:0x48].decode('utf-8'))
            target_evidence_item_id = bytes.fromhex(block[0x48:0x68].decode('utf-8'))
            target_creator = block[0x74:0x80]
            
            # Obtain the data from the original block
            dataLength = block[0x8c: 0x90]
            target_data = f.read(int.from_bytes(dataLength, 'little'))
        
        # Create the new block, write it
        updatedBlock = Block(self.get_last_block_hash(), "CHECKEDIN".encode('utf-8'), target_data, self.aes_key, target_case_id, target_evidence_item_id, target_creator, target_owner, rawBytes=True)
        updatedBlock.write_block(self.path)

        return decrypt_uuid(target_case_id, self.aes_key)

    def checkout(self, indexOfEvidence, owner):
        target_owner = b''
        target_case_id = b''
        target_evidence_item_id = b''
        target_creator = b''
        dataLength = b''
        target_data = b''
        
        # Open the file
        with open(self.path, 'rb') as f:
            # Jump to the target block
            f.seek(indexOfEvidence)
            block = f.read(0x90)

            target_case_id = bytes.fromhex(block[0x28:0x48].decode('utf-8'))
            target_evidence_item_id = bytes.fromhex(block[0x48:0x68].decode('utf-8'))
            target_creator = block[0x74:0x80]
            target_owner = owner.encode() + (12 - len(owner)) * b'\x00'
            dataLength = block[0x8c: 0x90]
            target_data = f.read(int.from_bytes(dataLength, 'little'))
        
        # Create the new block, write it
        updatedBlock = Block(self.get_last_block_hash(), "CHECKEDOUT".encode('utf-8'), target_data, self.aes_key, target_case_id, target_evidence_item_id, target_creator, target_owner, rawBytes=True)
        updatedBlock.write_block(self.path)

        return decrypt_uuid(target_case_id, self.aes_key)
 
    def get_cases(self):
        # Initialize the set of cases
        caseSet = set()

        # Open the file
        with open(self.path, 'rb') as f:
            # Loop through each block
            while True:
                # Obtain each block, stopping the loop if none is found
                block = f.read(0x90)
                if (not block):
                    break
                
                # Obtain the state
                state = block[0x68: 0x74]
                
                # If the state is not initial, save the case_id into the set
                if (state.strip(b'\x00').decode('utf-8') != 'INITIAL'):
                    decrypted_case_id = decrypt_uuid(bytes.fromhex(block[0x28:0x48].decode('utf-8')), self.aes_key)
                    caseSet.add(decrypted_case_id)

                # Navigate past the data
                data_length = block[0x8c : 0x90]
                f.seek(int.from_bytes(data_length, 'little'), 1)

        # Return the set of cases
        return caseSet

    def get_items(self, target_case_id):
        # Declare the set of items
        itemSet = set()

        # Open the file
        with open(self.path, 'rb') as f:
            # Loop through each block
            while True:
                # Grab the block, ending the loop if none is found
                block = f.read(0x90)
                if(not block):
                    break

                # Grab the state and decrypt the case id from the block
                state = block[0x68: 0x74]
                decrypted_case_id = decrypt_uuid(bytes.fromhex(block[0x28:0x48].decode('utf-8')), self.aes_key)
                
                # If the state is not initial and the case id matches, save the item
                if (state.strip(b'\x00').decode('utf-8') != 'INITIAL' and decrypted_case_id == uuid.UUID(target_case_id)):
                    decrypted_item = decrypt_evidence_id(bytes.fromhex(block[0x48:0x68].decode('utf-8')), self.aes_key)
                    itemSet.add(decrypted_item)

                # Jump past the data
                data_length = block[0x8c : 0x90]
                f.seek(int.from_bytes(data_length, 'little'), 1)

        # Return the set of items found
        return itemSet


    def get_history(self, caseID, itemID, numEntries, isReversed, owner):
        # Declare the list of tuples
        history = list(tuple())

        maxIter = -1
        stops = False
        if (numEntries != ''):
            maxIter = int(numEntries)
            stops = True
        currIndex = 0

        # Open the file
        with open(self.path, 'rb') as f:
            # Loop over each block
            while True:
                # If the max number of entries was defined and passed, break
                if (stops and currIndex >= maxIter):
                    break

                # Initialize the filters for cases and items
                caseMatch = caseID == ""
                itemMatch = itemID == ""

                # Grab the block, stopping the loop if none found
                block = f.read(0x90)
                if (not block):
                    break

                # Grab the state and timestamp
                state = block[0x68:0x74].strip(b'\x00').decode('utf-8')
                timestamp = datetime.datetime.fromtimestamp(struct.unpack('d', block[0x20:0x28])[0]).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                blockCaseID = b''
                blockItemID = b''

                # Decrypt the caseID and itemID
                decryptedCaseID = str(decrypt_uuid(bytes.fromhex(block[0x28:0x48].decode('utf-8')), self.aes_key))
                decryptedItemID = str(decrypt_evidence_id(bytes.fromhex(block[0x48:0x68].decode('utf-8')), self.aes_key))

                # If using the initial blocks, fill the tuple data with the initial data
                if (state == 'INITIAL'):
                    blockCaseID = '0' * 8 + '-' + '0' * 4 + '-' + '0' * 4 + '-' + '0' * 4 + '-' + '0' * 12
                    blockItemID = '0'
                    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                # If a valid password was entered, use the decrypted data
                elif (owner != ''):
                    blockCaseID = decryptedCaseID
                    blockItemID = decryptedItemID
                # Otherwise use the encrypted data
                else:
                    blockCaseID = block[0x28:0x48].decode('utf-8')
                    blockItemID = block[0x48:0x68].decode('utf-8')

                # Skip past the data
                data_length = block[0x8c : 0x90]
                f.seek(int.from_bytes(data_length, 'little'), 1)

                # Determine whether the case or item filters match if they were given
                caseMatch = caseMatch or decryptedCaseID == caseID
                itemMatch = itemMatch or decryptedItemID == itemID
                
                # If the filters dont catch the case and item, save to the list
                if (caseMatch and itemMatch):
                    # If reverse, insert at the beginning
                    if (isReversed):
                        history.insert(0, ("Case: " + blockCaseID, 
                                        "Item: " + blockItemID, 
                                        "Action: " + state, 
                                        "Time: " + timestamp))
                    # If not, insert at the end
                    else:
                        history.append(("Case: " + blockCaseID, 
                                        "Item: " + blockItemID, 
                                        "Action: " + state, 
                                        "Time: " + timestamp))
                
                # Increment the index if needed
                currIndex += 1

        # Return the list of tuples
        return history

    def remove(self, indexOfEvidence, reason_state):
        target_owner = b''
        target_case_id = b''
        target_evidence_item_id = b''
        data_length = b''
        target_data = b''
        
        # Open the file
        with open(self.path, 'rb') as f:
            # Grab the block
            f.seek(indexOfEvidence)
            block = f.read(0x90)

            # Copy the values necessary
            target_owner = block[0x80:0x8c]
            target_case_id = bytes.fromhex(block[0x28:0x48].decode('utf-8'))
            target_evidence_item_id = bytes.fromhex(block[0x48:0x68].decode('utf-8'))
            target_creator = block[0x74:0x80]

            data_length = block[0x8c:0x90]
            target_data = f.read(int.from_bytes(data_length, 'little'))
        
        # Create the new block with the given reason for removal, writing it
        updatedBlock = Block(self.get_last_block_hash(), reason_state.encode('utf-8'), target_data, self.aes_key, target_case_id, target_evidence_item_id, target_creator, target_owner, rawBytes=True)
        updatedBlock.write_block(self.path)
            