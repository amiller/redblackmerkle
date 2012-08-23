import os.path
import itertools
from itertools import imap, chain
from binascii import hexlify
from Crypto.Hash import SHA256

from bitcointools.deserialize import parse_Block, parse_BlockHeader, parse_Transaction
from bitcointools.block import scan_blocks, _open_blkindex, read_block
from bitcointools.util import create_env
from bitcointools.BCDataStream import BCDataStream

import struct

import redblack
reload(redblack)
from redblack import MerkleRedBlack, HashTableRB

import utxo_merkle
reload(utxo_merkle)
from utxo_merkle import genesis, DuplicateElementError, utxo_hash, MerkleNodeDigest

import json

#import leveldb_traversal
#reload(leveldb_traversal)
#import leveldb

db_dir = "/home/amiller/.bitcoin/testdb"
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
        hash_cache = []
    
        def scan_callback(block_data):
            hash_cache.append(block_data['hash256'])
            return not block_data['nHeight'] == 0

        scan_blocks(db_dir, db_env, scan_callback)

    cursor = db.cursor()
    for h in hash_cache[::-1]:
        #print hexlify(h[::-1])
        yield read_block(cursor, h)

def transactions_in_block(block_data):
    #print 'Block: ', block_data['nHeight'], hexlify(block_data['hash256'][::-1])
    block_datastream.seek_file(block_data['nBlockPos'])
    vds = block_datastream
    d = parse_BlockHeader(vds)
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


def apply_transaction(RB, D, (nHeight, tx_id, txn)):
    # Remove all the spent txins
    #print 'Applying txn:', hexlify(tx_id[::-1])
    for txin in txn['txIn']:
        prevout_hash = txin['prevout_hash']
        prevout_n = txin['prevout_n']

        if prevout_hash == genesis: continue # Ignore coinbase txns

        key = ("UTXO", prevout_hash, prevout_n)

        if 0:
            (_,utxo) = RB.search(key, D)
            serial = struct.pack("<4s32sI32s", "UTXO", tx_id, prevout_n, utxo)
            print json.dumps(["delete", hexlify(serial)])

        D = RB.delete(key, D)
        #print 'Deleted: ', ("TXID", hexlify(prevout_hash[::-1]), prevout_n)

    # Insert all the new txouts
    for idx,txout in enumerate(txn['txOut']):
        try:
            v = utxo_hash(idx==0, nHeight, txout['value'], txout['scriptPubKey'])
            D = RB.insert(("UTXO", tx_id, idx), D, v)

            if 0:
                serial = struct.pack("<4s32sI32s", "UTXO", tx_id, idx, v)
                print json.dumps(["insert", hexlify(serial)])

        except DuplicateElementError as e:
            pass # Ignore duplicate elements (relevant prior to BIP30)
        #print 'Inserted: ', ("TXID", hexlify(tx_id[::-1]), idx)

    return D


import numpy as np
import leveldb
import cPickle as pickle

if not 'hashtable' in globals():
    hashtable = leveldb.LevelDB('./bitcoin/bitcoin_hashtable')

class LevelDict(object):
    def __init__(self, db):
        self.db = db

    def __getitem__(self, k):
        return pickle.loads(self.db.Get(k))

    def __setitem__(self, k, v):
        self.db.Put(k, pickle.dumps(v,-1))

from binascii import unhexlify
def main():
    # Start with an empty_tree
    global MerkleTree, Trees
    RB = HashTableRB(MerkleNodeDigest, table=LevelDict(hashtable), validate=True)

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
        RB = HashTableRB(MerkleNodeDigest, table=LevelDict(hashtable), validate=True)
        if i <= start: continue
        MerkleTree = apply_transaction(RB, MerkleTree, (nHeight,tx_id,txn))
        #utxo_size += len(txn['txOut']) - len([1 for txin in txn['txIn'] if txin['prevout_hash'] != genesis])
        #txouts += len(txn['txOut'])
        Trees.append(MerkleTree)
        print i, hexlify(MerkleTree)
        #if nHeight >= 200000: break
        if nHeight >= 1000: break
