import os.path
import itertools
from itertools import imap, chain
from binascii import hexlify
from Crypto.Hash import SHA256

from bitcointools.deserialize import parse_Block, parse_BlockHeader, parse_Transaction
from bitcointools.block import scan_blocks, _open_blkindex, read_block
from bitcointools.util import create_env
from bitcointools.BCDataStream import BCDataStream

import utxo_merkle
reload(utxo_merkle)
from utxo_merkle import RB, genesis, DuplicateElementError

record = RB.record
replay = RB.replay
insert = RB.insert
delete = RB.delete
search = RB.search

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
        yield read_block(cursor, h)

def transactions_in_block(block_data):
    print 'Block: ', block_data['nHeight'], hexlify(block_data['hash256'][::-1])
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
        yield tx_id, txn

transactions_in_order = lambda: chain.from_iterable(imap(transactions_in_block,
                                                         blocks_in_order()))


def apply_transaction(D, (tx_id, txn)):
    # Remove all the spent txins
    #print 'Applying txn:', hexlify(tx_id[::-1])
    for txin in txn['txIn']:
        prevout_hash = txin['prevout_hash']
        prevout_n = txin['prevout_n']

        if prevout_hash == genesis: continue # Ignore coinbase txns

        D = delete(("TXID", prevout_hash, prevout_n), D)
        #print 'Deleted: ', ("TXID", hexlify(prevout_hash[::-1]), prevout_n)

    # Insert all the new txouts
    for idx,txout in enumerate(txn['txOut']):
        try:
            D = insert(("TXID", tx_id, idx), D)
        except DuplicateElementError as e:
            pass # Ignore duplicate elements (relevant prior to BIP34)

        #print 'Inserted: ', ("TXID", hexlify(tx_id[::-1]), idx)

    return D
    
# Start with an empty_tree
MerkleTree = ()

def merkle_scan():
    # Return 
    pass
