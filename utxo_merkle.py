"""
  Andrew Miller <amiller@cs.ucf.edu> <amiller@dappervision.com>

  A balanced Merkle tree of Unspent TX-Outs. Also known as: coinbase commitment,
  and "flipping the chain."

"""

from Crypto.Hash import SHA256
from redblack import MerkleRedBlack, DuplicateElementError
import struct


# Genesis (sentinel value) is a hash of all zero bits, it's also the digest
# of an empty node
genesis = 32 * chr(0)

def Serialize((c, dL, (k,v), dR)):
    """
    This function defines the serialization format for each node in the 
    UTXO balanced merkle tree. This function is passed (as H) to RedBlack(H)
    in order to obtain a specialized RedBlackMerkleTree for this format.

    Args:
        D: a tree node, one of the following
           - ()                         (empty node)
           - (c, H(Left), (k,()), H(Right))  (branch node)
           - (c, H(()),   (k,v),  H(()))       (leaf node)

           where,
        
        c: the color, "R" or "B"
        k: the largest key in the left subtree (branch node) 
           or the actual key (leaf node)
        v: the value associated with each key


        There are two kinds of (key -> value) mappings:
        1. UTXO Validation
             ("UTXO", txhash, index)  ->  (hash of validation information)

        2. Address Queries
             ("ADDR", address, txhash, index)  ->  ()

        Keys are sorted by lexical ordering. Values are stored only in leaf nodes.


    Returns: 
        Digest: a 256 bit string (len(Digest)==32), output of SHA256


        Branch nodes are serialized according to the following format:

          (color, dL, (("UTXO", txhash, index),()), dR):
            [1 byte][1 byte][4 bytes][32 bytes][32 bytes][4 bytes][32 bytes]
               "^"    color   "UTXO"   H(Left)    txhash    index  H(Right) 
            total: 1+1+4+32+32+4+32 = 106 bytes

          (color, dL, (("ADDR", address, txhash, index), ()), dR):
            [1 byte][1 byte][4 bytes][32 bytes][20 bytes][32 bytes][4 bytes][32 bytes]
            [  "^" ][ color][ "ADDR"][ H(Left)][    addr][  txhash][  index][H(Right)]
            total: 1+1+4+32+20+32+4+32 = 126 bytes

        where:
          address is a 20-byte hash (only used for standard transactions)
          color is either "R" or "B" (ascii)
          index is an unsigned int, little endian
          "^" indicates a branch node


        Leaf nodes are serialized in a similar format, except with the left/right
        digests omitted, and the value appended. A different sentinel value, "." 
        instead of "^", is used to signify a leaf.

          (color, (), (("UTXO", txhash, index), utxohash), ()):
            [1 byte][1 byte][4 bytes][32 bytes][4 bytes][32 bytes]
               "."    color   "UTXO"    txhash    index  utxohash 
            total: 1+1+4+32+4+32 = 74 bytes

          (color, (), (("ADDR", address, txhash, index), ()), ()):
            [1 byte][1 byte][4 bytes][20 bytes][32 bytes][4 bytes]
               "."    color   "ADDR"      addr    txhash    index 
            total: 1+1+4+20+32+4 = 62 bytes


        There is a different value scheme associated with each key type. The 
        idea is that the value associated with a UTXO is sufficient to validate a 
        transaction that spends it. ADDR mappings contain all their information in 
        the key itself, so no separate value is required.

    """

    # Sanity checks
    if not dL: dL = genesis
    if not dR: dR = genesis
    assert type(dL) is str and len(dL) == 32
    assert type(dR) is str and len(dR) == 32
    assert c in ("R", "B")
    assert k[0] in ("UTXO", "ADDR")

    # UTXO table, indexed
    if k[0] == "UTXO":
        (_, txhash, index) = k
        assert type(txhash) is str and len(txhash) == 32
        assert type(index) is int and 0 <= index <= (1<<32)-1

        if dL == dR == genesis:
            # Leaf node
            assert type(v) is str and len(v) == 32
            serial = struct.pack("<cc4s32sI32s", '.', c, k[0], txhash, index, v)
            assert len(serial) == 74

        else:
            # Branch node
            assert not v
            serial = struct.pack("<cc4s32s32sI32s", '^', c, k[0], dL, txhash, index, dR)
            assert len(serial) == 106


    # ADDR table (standard txouts only)
    if k[0] == "ADDR":
        (_, addr, txhash, index) = k
        assert type(addr) is str and len(addr) == 20
        assert type(txhash) is str and len(txhash) == 32
        assert type(index) is int and 0 <= index <= (1<<32)-1
        assert not v

        if dL == dR == genesis:
            # Leaf node
            serial = struct.pack("<cc4s32s20s32sI32s", '.', c, k[0], dL, addr, txhash, index, dR)
            assert len(serial) == 126

        else:
            # Branch node
            serial = struct.pack("<c4s32s20s32sI32s", c, k[0], dL, addr, txhash, index, dR)
            assert len(serial) == 125

    return serial

def MerkleNodeDigest(D):
    serial = Serialize(D)
    return SHA256.new(serial).digest()


def utxo_hash(isCoinbase, nHeight, amount, scriptPubKey):
    """
    The information needed to validate a single UTXO is a subset of the 
    data in a transaction, in particular it is independent of the size of 
    the transaction (i.e., the total number of inputs and outputs).

    Args:
        isCoinbase:   boolean (0 or 1)
        nHeight:      unsigned int (4 bytes)
        amount:       unsigned int (4 bytes)
        scriptPubKey: str

    Returns:
        Digest, a 256 bit (SHA256) hash

        The data is serialized as follows:
             [    1 byte][4 bytes][8 bytes][     x bytes]
              isCoinbase  nHeight   amount  scriptPubKey
    """
    isCoinbase = int(bool(isCoinbase)) # Coerce to a one bit int
    assert type(nHeight) is int
    assert type(amount) in (int,long) and 0 <= amount < 21E14 # MAX_MONEY
    assert type(scriptPubKey) is str

    serial = struct.pack("<BIQs", isCoinbase, nHeight, amount, scriptPubKey)
    return SHA256.new(serial).digest()
