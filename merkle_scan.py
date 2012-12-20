import os.path
import itertools
from itertools import imap, chain
from binascii import hexlify
from Crypto.Hash import SHA256
from functools import partial

from collections import defaultdict
from bitcointools.deserialize import parse_Block, parse_BlockHeader, parse_Transaction
from bitcointools.block import scan_blocks, _open_blkindex, read_block
from bitcointools.util import create_env
from bitcointools.BCDataStream import BCDataStream

import struct

import redblack
reload(redblack)
from redblack import MerkleRedBlack, HashTableRB, RedBlack, RecordTraversal, ReplayTraversal

import utxo_merkle
reload(utxo_merkle)
from utxo_merkle import genesis, DuplicateElementError, utxo_hash, MerkleNodeDigest

import io
import json
import cPickle as pickle
import numpy as np
import leveldb
from binascii import unhexlify

#import leveldb_traversal
#reload(leveldb_traversal)
#import leveldb

db_dir = "./testdb"
db_env = create_env(db_dir)

if not 'block_datastream' in globals():
    blockfile = open(os.path.join(db_dir, "blk%04d.dat"%(1,)), "rb")
    block_datastream = BCDataStream()
    block_datastream.map_file(blockfile, 0)



def blocks_in_order():
    """ Yield all the blocks in chronological order, beginning with genesis
    """
    db = _open_blkindex(db_env)

    global hash_cache
    if not 'hash_cache' in globals():
        try:
            with open('hash_cache.pkl','r') as f: hash_cache = pickle.load(f)
        except IOError: pass

    if not 'hash_cache' in globals():
        hash_cache = []
    
        def scan_callback(block_data):
            hash_cache.append(block_data['hash256'])
            return not block_data['nHeight'] == 0

        scan_blocks(db_dir, db_env, scan_callback)

        with open('hash_cache.pkl','w') as f: pickle.dump(hash_cache, f)

    cursor = db.cursor()
    for h in hash_cache[::-1]:
        #print hexlify(h[::-1])
        yield read_block(cursor, h)


global block_index
if not 'block_index' in globals():
    block_index = {}

def height_index(block_index):
    index = defaultdict(set)
    for k,v in sorted((height, (sha256, fpos_start, fpos_end))
                      for (sha256, (height, fpos_start, fpos_end))
                      in block_index.iteritems()):
        index[k].add(v)
    return index

def read_one_block(f, skip=None, blkhash=None):
    if skip is not None: f.seek(skip)

    from pynode.bitcoin.core import CBlock
    from pynode.bitcoin.serialize import ser_uint256

    magic = f.read(4)
    assert magic == "\xf9\xbe\xb4\xd9"
    version = f.read(4)

    block = CBlock()
    block.deserialize(f)

    if blkhash is not None:
        block.calc_sha256()
        assert block.sha256 == blkhash

    return block

def longest_chain(height_index):
    length = max(height_index)
    if len(height_index[length]):
        print 'Multiple longest chains'
    _, (blkhash,start,end) = iter(height_index)

def scan_blocks():
    global block_index, bigfile
    #vds = io.FileIO(os.path.join(db_dir, "blk%04d.dat"%(1,)), "rb")
    vds = io.FileIO("/home/amiller/Downloads/bootstrap.dat", "rb")

    while True:

        start = vds.tell()
        block = read_one_block(vds)
        end = vds.tell()

        assert block.hashPrevBlock in block_index or block.hashPrevBlock == 0
        block.calc_sha256()

        height = block_index[block.hashPrevBlock][0]+1 if block.hashPrevBlock else 0
        block_index[block.sha256] = height,start,end

        yield height, block

def transactions_in_block(blkhash):
    open()
    print block_data
    nTransactions = vds.read_compact_size()
    for i in xrange(nTransactions):
        # Parse the transaction, recording the cursor position
        start = vds.read_cursor
        txn = parse_Transaction(vds)
        end = vds.read_cursor

        # Then reread it again to find the txn hash (txid)
        vds.seek_file(start)
        txdata = vds.read_bytes(end-start)
        tx_id = SHA256.new(SHA256.new(txdata).digest()).digest()
        yield block_data['nHeight'], tx_id, txn

transactions_in_order = lambda: chain.from_iterable(imap(transactions_in_block,
                                                         blocks_in_order()))

def ireduce(func, iterable, init=None):
    if init is None:
        iterable = iter(iterable)
        curr = iterable.next()
    else:
        curr = init
    for x in iterable:
        curr = func(curr, x)
        yield curr

def apply_update(RB, D, update):
    cmd, item = update
    if cmd == 'delete': 
        key = item
        return RB.delete(key, D)
    if cmd == 'insert':
        key, value = item
        try:
            return RB.insert(key, D, value)
        except DuplicateElementError as e:
            return D # Ignore duplicate elements (relevant prior to BIP30)

def updates_in_transaction(nHeight, tx_id, txn):
    #print 'Applying txn:', hexlify(tx_id[::-1])
    # Remove all the spent txins
    for txin in txn['txIn']:
        prevout_hash = txin['prevout_hash']
        prevout_n = txin['prevout_n']
        if prevout_hash == genesis: continue # Ignore coinbase txns
        key = ("UTXO", prevout_hash, prevout_n)
        yield ('delete', key)

    # Insert all the new txouts
    for idx,txout in enumerate(txn['txOut']):
        value = utxo_hash(idx==0, nHeight, txout['value'], txout['scriptPubKey'])
        key = ("UTXO", tx_id, idx)
        yield ('insert', (key, value))

if not 'hashtable' in globals():
    hashtable = leveldb.LevelDB('./bitcoin/bitcoin_hashtable')

class LevelDict(object):
    def __init__(self, db):
        self.db = db

    def __getitem__(self, k):
        return pickle.loads(self.db.Get(k))

    def __setitem__(self, k, v):
        self.db.Put(k, pickle.dumps(v,-1))

def accumulate_tree(D, txn):
    pass

def serialize_key(k):
    assert k[0] in ("UTXO",)
    return ':'.join(map(str, k))

def main():
    # Start with an empty_tree
    global MerkleTree, Trees
    #RB = HashTableRB(MerkleNodeDigest, table=LevelDict(hashtable), validate=True)
    RB = MerkleRedBlack(MerkleNodeDigest)
    #start = 226274; MerkleTree = unhexlify("8f19e9e653edbe752e346585bfbe10711ff372f9810e96df4c2fc9d306452bb1")
    #start = 216573; MerkleTree = unhexlify("ac3b14a1a4295ce58b27d5eb6925364ec5f75e39ad0fc4a211fb76895776dc42")
    #start = 175005; MerkleTree = unhexlify("e4ca15dd2b5f8063e340ed884924a9355719fb341a7a4bdc513d173ab609ec0b")
    #start = 128285; MerkleTree = unhexlify("74ac1d7315faa41b21ef8546e6baed5dc50d29fbd28f07d796c2b8141770dd2a")
    #start = 26528; MerkleTree = unhexlify('4f56e9c4f27b8acd59beb7dac8236602107b957e96422cbb8974e1d787cd2425')
    #start = 10092; MerkleTree = unhexlify('06fcf352f291a6f7242590266c0d80ca6514b779f8b9c4803887c0bf415b028c')
    #start = 1532; MerkleTree = unhexlify('c52fe74601b83ef8e55c138293741901ae474d34d7dbf344713f0a21bbc5fe5c')
    start = -1; MerkleTree = RB.E

    txs = transactions_in_order()

    Trees = []
    utxo_size = 0
    txouts = 0
    for i,(nHeight,tx_id,txn) in enumerate(txs):
        #RB = HashTableRB(MerkleNodeDigest, table=LevelDict(hashtable), validate=True)
        RB = MerkleRedBlack(MerkleNodeDigest)
        if i <= start: continue
        MerkleTree = reduce(partial(apply_update, RB),
                            updates_in_transaction(nHeight,tx_id,txn), MerkleTree)
        #utxo_size += len(txn['txOut']) - len([1 for txin in txn['txIn'] if txin['prevout_hash'] != genesis])
        #txouts += len(txn['txOut'])
        #Trees.append(MerkleTree)
        print i, hexlify(MerkleTree[0])
        #if nHeight >= 200000: break
        if nHeight >= 1000: break
    #print hash(tuple(RB.preorder_traversal(MerkleTree)))


class CounterRedBlack(RedBlack):
    """Pass-through context (Identity)
    """
    def __init__(self, E=(), emit=None):
        self.get_count = 0
        self.put_count = 0
        if emit is None:
            self.VO = []
            emit = self.VO.append
        self.emit = emit
        super(CounterRedBlack,self).__init__(((),E))

    def store(self, c, (dL,L), k, (dR,R)):
        self.put_count += 1
        return ((self.get_count, self.put_count-1), (c, (dL,L), k, (dR,R)))

    def get(self, ((get_count, put_count),D)):
        print 'put:', put_count, 'get:', self.get_count, 'diff:', self.get_count - get_count
        self.emit((self.get_count, put_count, self.get_count-get_count))
        self.get_count += 1
        return D

def main2(stop=1532):
    # Run through the blockchain, updating a redblack tree of UTXO keys (no hashes, no values)
    global MerkleTree, RB
    #RB = RedBlack()
    RB = CounterRedBlack()
    start = -1; MerkleTree = RB.E
    txs = transactions_in_order()
    for i,(nHeight,tx_id,txn) in enumerate(txs):
        if i <= start: continue
        MerkleTree = reduce(partial(apply_update, RB),
                            updates_in_transaction(nHeight,tx_id,txn), MerkleTree)
        print nHeight, i
        if nHeight >= stop: break
    print hash(tuple(RB.preorder_traversal(MerkleTree)))

def main3():
    global MerkleTree
    RB = RedBlack()
    start = -1; MerkleTree = RB.E
    txs = transactions_in_order()
    for i,(nHeight,tx_id,txn) in enumerate(txs):
        if i <= start: continue
        MerkleTree = reduce(partial(apply_update, RB),
                            updates_in_transaction(nHeight,tx_id,txn), MerkleTree)
        print nHeight, i
        if nHeight >= stop: break
    print hash(tuple(RB.preorder_traversal(MerkleTree)))

import cPickle as pickle
def demo_record():
    # Start with an empty_tree
    global MerkleTree, Trees, RB
    #RB = HashTableRB(MerkleNodeDigest, table=LevelDict(hashtable), validate=True)
    RB = MerkleRedBlack(MerkleNodeDigest)
    start = -1; MerkleTree = RB.E

    txs = transactions_in_order()

    Trees = []
    utxo_size = 0
    txouts = 0
    RB = RecordTraversal(MerkleNodeDigest)
    with open('testdb/vofile.json','w') as vofile:
      for i,(nHeight,tx_id,txn) in enumerate(txs):
        if i <= start: continue
        RB = RecordTraversal(MerkleNodeDigest)
        #RB = HashTableRB(MerkleNodeDigest, table=LevelDict(hashtable), validate=True)
        #RB = MerkleRedBlack(MerkleNodeDigest)
        MerkleTree = reduce(partial(apply_update, RB),
                            updates_in_transaction(nHeight,tx_id,txn), MerkleTree)
        #vo = pickle.dumps(RB.VO)
        #vofile.write(vo)
        print nHeight, i, hexlify(MerkleTree[0])
        if nHeight > 0x100000: break

def perturb(vo):
    while True:
        try:
            s = pickle.dumps(vo)
            i = random.randint(0, len(s))
            s = s[:i] + chr(0) + s[i+1:]
            vo = pickle.loads(s)
            return vo
        except EOFError:
            continue
        except ValueError:
            continue


def demo_replay():
    RB = HashTableRB(MerkleNodeDigest)
    MerkleTree = RB.E
    txs = transactions_in_order()
    with open('./testdb/vofile_132267.json','r') as vofile:
      for i,(nHeight,tx_id,txn) in enumerate(txs):
        #RB = HashTableRB(MerkleNodeDigest, table=LevelDict(hashtable), validate=True)
        #RB = MerkleRedBlack(MerkleNodeDigest)
        vo = pickle.load(vofile)
        import random
        if random.random() < 0.00: vo = perturb(vo) # Random fuzz-test errors
        RB = ReplayTraversal(vo, MerkleNodeDigest)
        MerkleTree = reduce(partial(apply_update, RB),
                            updates_in_transaction(nHeight,tx_id,txn), MerkleTree)
        print nHeight, i, len(vo), hexlify(MerkleTree)
        if nHeight > 1532: break


class AppendOnlyFile(object):
    def __init__(self, path):
        self._writer = open(path, 'a+b')
