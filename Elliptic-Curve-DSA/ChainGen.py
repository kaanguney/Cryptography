# -*- coding: utf-8 -*-

import math
import random
import string
import warnings
import os.path
import sys
from Crypto.Hash import SHA3_256

# MerkleTree implementation
# TxCnt is the number of transactions
def tree(TxCnt,Block):
  hashTree = []
  for i in range(0,TxCnt):
    transaction = "".join(Block[i*9:(i+1)*9])
    hashTree.append(SHA3_256.new(transaction.encode('UTF-8')).digest())
  t = TxCnt
  j = 0
  while(t>1):
    for i in range(j,j+t,2):
      hashTree.append(SHA3_256.new(hashTree[i]+hashTree[i+1]).digest())
    j += t
    t = t>>1

  return hashTree[2*TxCnt-2]

# simple class to connect prev with nex proof of work
class Prev:
    prv = ""

# only function in this .py file 
def AddBlock2Chain(PoWLen, TxCnt, block_candidate, PrevBlock):

  hash_root = 0 
  zeros = ""
  NewBlock = ""
  previous = ""
  currPoW = ""

  # construct a checker for zeros
  for k in range(PoWLen):
      zeros += "0"

  hash_root = tree(TxCnt,block_candidate) # get Merkle root

  # for first chain 
  if(PrevBlock == ""):
    previous = "00000000000000000000"
    while(currPoW[:PoWLen] != zeros):
      # calculate the current PoW
      nonce = random.getrandbits(128) # choose nonce as a 128-bit random integer
      hashformat = hash_root + str.encode(previous) + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder = 'big')
      hashval = SHA3_256.new()
      hashval.update(hashformat)
      # convert hashval to the str format for PoW comparison 
      currPoW = hashval.hexdigest()

    # now, current PoW is found...
    # construct NewBlock now...
    for x in range(len(block_candidate)):
      NewBlock += block_candidate[x]
    NewBlock += ("Previous PoW: " + str(previous) + "\n" + "Nonce: " + str(nonce) + "\n")
    Prev.prv = currPoW # connect the previous PoW with the current PoW
    return NewBlock, previous
  
  # if the previous block is not the first block
  else:
    previous = Prev.prv
    while(currPoW[:PoWLen] != zeros):
      # calculate the current PoW
      nonce = random.getrandbits(128) # choose nonce as a 128-bit random integer
      hashformat = hash_root + str.encode(previous) + nonce.to_bytes((nonce.bit_length()+7)//8, byteorder = 'big')
      hashval = SHA3_256.new()
      hashval.update(hashformat)
      # convert hashval to the str format for PoW comparison 
      currPoW = hashval.hexdigest()

    # now, current PoW is found...
    # construct NewBlock now...
    for x in range(len(block_candidate)):
      NewBlock += block_candidate[x]
    NewBlock += ("Previous PoW: " + str(previous) + "\n" + "Nonce: " + str(nonce)+ "\n")
    Prev.prv = currPoW # connect the previous PoW with the current PoW
    return NewBlock, previous
    
# end of implementation
