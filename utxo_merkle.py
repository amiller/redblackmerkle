"""
  Andrew Miller <amiller@cs.ucf.edu> <amiller@dappervision.com>

  A balanced Merkle tree of Unspent TX-Outs. Also known as: coinbase commitment,
  and "flipping the chain."

"""

from Crypto.Hash import SHA256
import struct

from redblack import RedBlack

# Genesis (sentinel value) is a hash of all zero bits, it's also the digest
# of an empty node
genesis = bytearray(32 * chr(0))

def MerkleNodeDigest(D):
    """
    This function defines the serialization format for each node in the 
    UTXO balanced merkle tree. This function is passed (as H) to RedBlack(H)
    in order to obtain a specialized RedBlackMerkleTree for this format.

    Args:
        D: a tree node, one of the following
           - ()                         (empty node)
           - (c, H(Left), k, H(Right))  (branch node)
           - (c, H(()), k, H(()))       (leaf node)

           where,
        
        c: the color, "R" or "B"
        k: the largest key in the left subtree (branch node) 
           or the actual key (leaf node)

        keys are of the form:
             ("TXID", txhash, index)   utxos, indexed by txid, for validation

        or,
             ("ADDR", address, txhash, index) utxos, indexed by address

        keys are sorted by lexical ordering in this format

    Returns: 
        Digest: a 256 bit bytearray (len(Digest)==32), output of SHA256

        Nodes are serialized according to the following format:

         (color, dL, ("TXID", txhash, index), dR):
           [ 1 byte ][ 4 bytes ][ 32 bytes ][ 32 bytes ][ 4 bytes ][ 32 bytes ]
           [  color ][  "TXID" ][  H(Left) ][   txhash ][   index ][ H(Right) ]
           total: 1+4+32+32+4+32 = 105 bytes

         (color, dL, ("ADDR", address, txhash, index), dR):
           [ 1 byte ][ 4 bytes ][ 32 bytes ][ 20 bytes ][ 32 bytes ][ 4 bytes ][ 32 bytes ]
           [  color ][  "TXID" ][  H(Left) ][     addr ][   txhash ][   index ][ H(Right) ]
           total: 1+4+32+20+32+4+32 = 125 bytes

         address is a 20-byte hash (only used for standard transactions)
         color is either "R" or "B" (ascii)
         index is an unsigned int, little endian

    """

    # Empty node
    if not D: return genesis

    # Otherwise, it's a branch or a leaf. No need for a separate case.
    (c, dL, k, dR) = D

    # Sanity checks
    assert type(dL) is bytearray and len(dL) == 32
    assert type(dR) is bytearray and len(dR) == 32
    assert c in ("R", "B")
    assert k[0] in ("TXID", "ADDR")

    # UTXO table, indexed by TXID
    if k[0] == "TXID":
        (_, txhash, index) = k
        assert type(txhash) is bytearray and len(txhash) == 32
        assert type(index) is int and 0 <= index <= (1<<32)-1
        serial = struct.pack("ssssc<4is", c, k[0], dL, txhash, index, dR)
        assert len(serial) == 105

    # UTXO table, indexed by address (standard TXOUT only)
    if k[0] == "ADDR":
        (_, addr, txhash, index) = k
        assert type(addr) is bytearray and len(addr) == 20
        assert type(txhash) is bytearray and len(txhash) == 32
        assert type(index) is int and 0 <= index <= (1<<32)-1
        serial = struct.pack("sssssc<4is", c, k[0], dL, addr, txhash, index, dR)
        assert len(serial) == 125
        
    # Hash it up
    return bytearray(SHA256.new(serial).digest())

# Use this digest function to create a specialized instance of the RedBlack tree
RB = RedBlack(MerkleNodeDigest)
