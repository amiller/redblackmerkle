import unittest; reload(unittest)
import random
from Crypto.Hash import SHA256
import json
import redblack; reload(redblack)
from redblack import RedBlack, MerkleRedBlack, HashTableRB
from redblack import RecordTraversal, ReplayTraversal

def demo_normal():
    RB = RedBlack()

    D = RB.E
    print D
    for i in range(10):
        D = RB.insert(i, D)
    print D
    for i in range(10):
        D = RB.delete(i, D)
    print D

def demo_merkle():
    RB = MerkleRedBlack()
    D = RB.E
    print D
    for i in range(10):
        D = RB.insert(i, D)
    print D

def demo_hashtable():
    RB = HashTableRB()
    D = RB.E
    print D
    for i in range(10):
        D = RB.insert(i, D)
        print D
    

def demo_recordreplay():
    RB = MerkleRedBlack()
    D = RB.E
    print D
    for i in range(10):
        D = RB.insert(i, D)
    print D

    roothash = D[0]

    record = RecordTraversal()
    for i in range(10):
        D = record.delete(i, D)
    print D
    print record.VO

    replay = ReplayTraversal(record.VO)
    D = roothash
    for i in range(9):
        D = replay.delete(i, D)
    print D

def demo_hashsoup(table={}):
    # Create N trees
    N = 100
    inds = range(N)
    import random
    random.shuffle(inds)
    RB = HashTableRB(table=table)
    D = RB.E
    index = [D]
    for i in inds:
        D = RB.insert(i, D)
        index.append(D)

    index2 = [RB.E]
    for D,i in zip(index,inds):
        D = RB.insert(i, D)
        index2.append(D)

    assert index == index2

    D = RB.reconstruct(index[1])
    print D, index[1]

import leveldb
db = leveldb.LevelDB('testdb')
class LevelDict(object):
    def __init__(self, db):
        self.db = db

    def __getitem__(self, k):
        return eval(self.db.Get(repr(k)))

    def __setitem__(self, k, v):
        self.db.Put(repr(k), repr(v))
        
    
#demo_recordreplay()
