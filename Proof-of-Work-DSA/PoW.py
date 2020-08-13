import random # for nonce
import warnings 
from Crypto.Hash import SHA3_256 # for hashing

# MerkleTree implementation
# input is the transactions chosen 

def MerkleTree(ChosenTransactions,merkle_size): 

  Merkle = []

  for k in range(0,merkle_size-1,2):

    transaction1 = ChosenTransactions[k]
    transaction2 = ChosenTransactions[k+1]

    # hashing start...
    hash1 = SHA3_256.new()
    hash1.update(str.encode(transaction1))
    h1 = int.from_bytes(hash1.digest(), byteorder='big') # conversion from bytes to integer
    hash2 = SHA3_256.new()
    hash2.update(str.encode(transaction2))
    h2 = int.from_bytes(hash2.digest(), byteorder='big') # conversion from bytes to integer
    # hashing end...

    Merkle.append(h1)
    Merkle.append(h2)
  
  # first round of transactions stored in MerkleTree
  # now,climb up the tree by adding the hashes together and hashing them together

  MerkleTempStore = [] # temporary storer 

  terminate = True

  while(terminate):

    treesize = len(Merkle) # size of the MerkleTree, included here for assignment

    if(treesize == 1):

      terminate = False

    for k in range(0,treesize-1,2):

      transaction1 = Merkle[k]
      transaction2 = Merkle[k+1]

      hashed = transaction1 + transaction2 # add the hashes as you climb the tree and hash again 
      hash_bytes = hashed.to_bytes((hashed.bit_length()+7)//8, byteorder = 'big')
      # hash again..
      obj = SHA3_256.new()
      obj.update(hash_bytes)
      hashedobj = int.from_bytes(obj.digest(), byteorder='big') # conversion from bytes to integer

      MerkleTempStore.append(hashedobj) # add to the temporary storer

    if(len(Merkle) != 1): # in order not reset for the last element in MerkleTree

      Merkle = MerkleTempStore # construct Merkle again

    MerkleTempStore = [] # reset here

  # now, Merkle's only element will give us the hash root 

  return Merkle[0]

# read from transactions.txt and compute a PoW for the block
# PowLen is at least 5
# once you find the PoW for the block, add the nounce and write it to a file called "block.txt"

def PoW(PoWLen, q, p, g, TxCnt, filename):

  ChosenTransactions = [] 

  transaction = ""

  with open(filename,"r") as f:
  
    transactions = f.readlines()

    counter = 0 # iterator for fixed number of transactions 

    # each transaction block length is 7 lines 

    # for the first block

    hold = 0 

    for k in range(7):

      transaction += transactions[k]

      hold = k 
    
    counter += 1 # first transaction processed

    ChosenTransactions.append(transaction)

    hold += 1 # assign to the preceeding index

    transaction = "" # reset 

    # for the second block

    while(hold < 14):

      transaction += transactions[hold]

      hold += 1
      
    counter += 1 # second transaction processed

    ChosenTransactions.append(transaction)

    transaction = "" # reset 

    # for the remaining transactions

    terminate = True

    while(terminate):

      if(counter == (TxCnt-1)): # transaction split done

        terminate = False

      blockrange = hold + 7

      while(hold < blockrange):

        transaction += transactions[hold]

        hold += 1

      ChosenTransactions.append(transaction)

      transaction = "" # reset 

      counter += 1 # new transaction added
      
  f.close()

  # chosen transactions now are stored in an array...

  merkle_size = len(ChosenTransactions)

  # use the MerkleTree implementation here

  hash_root = MerkleTree(ChosenTransactions,merkle_size) # hashroot returned as integer type

  proof = "" # just assignment

  checker = ""

  for k in range(PoWLen):

    checker += "0"

  while(proof[:PoWLen] != checker):

    nonce = random.getrandbits(128) # choose nonce as a 128-bit random integer
    concatenated = nonce + hash_root  # add the hash and nonce, then final hash to obtain special form
    hashformat = concatenated.to_bytes((concatenated.bit_length()+7)//8, byteorder = 'big')
    hashval = SHA3_256.new()
    hashval.update(hashformat)
    # convert hashval to the str format for PoW comparison 
    proof = hashval.hexdigest()

  # once this loop terminates, PoW found for the block...

  block = "" # append the nonce in the end to the selected transactions and write to block.txt

  len_block = len(ChosenTransactions)
  
  write_contents = ""

  for k in range(len_block):

    write_contents += ChosenTransactions[k] # add all selected transactions here

  # finally, add the nonce to to the block and write to "block.txt"

  write_contents += "Nonce : " + str(nonce) + "\n"

  return write_contents

# TxCnt -> the number of transactions in the filename
# returns an empty string if PoW of the block of transactions in “filename’ does not have preceding PoWLen hexadecimal 0s
# Otherwise, it returns the value of PoW

def CheckPow(p, q, g, PoWLen, TxCnt, filename):

  ChosenTransactions = [] 

  transaction = ""

  with open(filename,"r") as f:
  
    transactions = f.readlines()

    counter = 0 # iterator for fixed number of transactions 

    # each transaction block length is 7 lines 

    # for the first block

    hold = 0 

    for k in range(7):

      transaction += transactions[k]

      hold = k 
    
    counter += 1 # first transaction processed

    ChosenTransactions.append(transaction)

    hold += 1 # assign to the preceeding index

    transaction = "" # reset 

    # for the second block

    while(hold < 14):

      transaction += transactions[hold]

      hold += 1
      
    counter += 1 # second transaction processed

    ChosenTransactions.append(transaction)

    transaction = "" # reset 

    # for the remaining transactions

    terminate = True

    while(terminate):

      if(counter == (TxCnt-1)): # transaction split done

        terminate = False

      blockrange = hold + 7

      while(hold < blockrange):

        transaction += transactions[hold]

        hold += 1

      ChosenTransactions.append(transaction)

      transaction = "" # reset 

      counter += 1 # new transaction added
      
  f.close()

  # chosen transactions now are stored in an array...

  merkle_size = len(ChosenTransactions)

  # use the MerkleTree implementation here

  hash_root = MerkleTree(ChosenTransactions,merkle_size) # hashroot returned as integer type

  proof = "" # just assignment

  checker = ""

  for k in range(PoWLen):

    checker += "0"

  while(proof[:PoWLen] != checker):

    nonce = random.getrandbits(128) # choose nonce as a 128-bit random integer value 
    concatenated = nonce + hash_root  # add the hash and nonce, then final hash to obtain special form
    hashformat = concatenated.to_bytes((concatenated.bit_length()+7)//8, byteorder = 'big')
    hashval = SHA3_256.new()
    hashval.update(hashformat)
    # convert hashval to the str format for PoW comparison 
    proof = hashval.hexdigest()

  # once this loop terminates, PoW found for the block...

  # if format is correct, return the value

  if(proof[:PoWLen] == checker):

    return proof 

  # if format is wrong, return an empty string 

  else:

    return ""
