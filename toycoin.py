"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012


An alternate proof-of-work scheme for Bitcoin. Instead of merely computing
hashes, miners compete by demonstrating high-throughput access to their
'unspent coins' database.

This is achieved by storing each 'unspent coin' as an element in a data-
structure such that elements can be selected pseudo-randomly (uniformly)
and verified against a known digest (i.e., the root hash of a Merkle tree).
The work consists of k iterations where the data for each selected element
is used to determine the selection for next iteration.

The only way to build a machine that's good at producing this proof-of-work
is to build a machine that's also efficient at validating transactions. This
will increase the decentralized of Bitcoin, since the cost of maintaining
the 'unspent coins' database is currently 'unpaid overtime', so-to-speak. In
fact, many miners participate in pools without storing their own copy of the
state, foregoing their ability to independently verify transactions.


D:
    An 'Unspent Inputs' database. It's an AuthSelectRedBlack.

Tx:
    A transaction. Consists of inputs and outputs

        (Input, Outputs, Signatures) = Tx
        (inps, outs, sigs) = Tx

    where Outputs is an array of the newly formed 'coins':

        total_out = sum(Amount for (PubKey, Amount) in Outputs)

    and the inputs are references to outputs from previous transactions:

        for inp, sig in zip(Inputs):
            (pub, amt), VO = query_unspent(inp, D)
            assert verify_signature(pub, sig)
            assert amt > 0

    For a transaction to be valid, the signature must match the public keys
    for all the inputs and the amount of tokens going out must exactly match
    the value of the tokens coming in.


It gets slightly more complicated. Since the _authoritative_ version of
transaction commits is decided by the longest chain of blocks, it's also
essential for miners to store (at least some sliding window of) the blockchain
history.


C:
    A block chain
        (

B:
    A Block consists of a sequence of transactions, along with the digest of
    a previous block (forming a chain) and a winning solution to the
    proof-of-work puzzle.

        (dPrev, Txs, Nonce) = B
    
"""

from proofofthroughput import do_work, verify_work
from redblack import RedBlack

import random
PRNG = lambda seed: random.Random(seed)

from Crypto.Hash import SHA256


class Transaction():

    def __init__(self, verify_signature, block_window=None):
        self.verify_signature = verify_signature
        self.block_window = block_window
        H = lambda x: '' if not x else SHA256.new(str(x)).hexdigest()[:8]
        self.H = H
        self.RB = RB = RedBlack(H)
        self.size = RB.size
        self.search = RB.search
        self.digest = RB.digest
        self.select = RB.select
        self.insert = RB.insert
        self.delete = RB.delete
        self.reconstruct = RB.reconstruct


    """
    Transactions and unspent-inputs database
    ========================================
    """

    def digest_transaction(self, Tx):
        (inps, outps, sigs) = Tx
        return self.H((inps, outps))  # Exclude sig from the digest


    def apply_transaction(self, Tx, D):
        """
        Updates the tree and returns a Verification Object that can
        be used to simulate the transaction
        """
        (inps, outs, sigs) = Tx
        dTx = self.digest_transaction(Tx)

        # First delete each of the old inputs
        inpPs = []
        for inp in inps:
            v, _ = self.search((inp,None), D)
            D, P = self.delete(v, D)
            inpPs.append(P)

        # Then insert each of the new outputs
        outPs = []
        for i, v in enumerate(outs):
            D, P = self.insert(((dTx,i), v), D)
            outPs.append(P)

        return D, (inpPs, outPs)
    

    def verify_transaction(self, d0, Tx, VO):
        (inps, outs, sigs) = Tx
        (inpPs, outPs) = VO
        dTx = self.digest_transaction(Tx)

        total_out = sum(amt for (_, amt) in outs)
        total_in = 0

        # First simulate removing each of the old inputs
        assert len(inps) == len(sigs) == len(inpPs)
        for inp, P, sig in zip(inps, inpPs, sigs):
            R = self.reconstruct(d0, P)
            (_inp, (pub, amt)), _ = self.search((inp, None), R)
            assert _inp == inp
            assert self.verify_signature(dTx, pub, sig)
            assert amt > 0
            total_in += amt
            d0 = self.digest(self.delete((inp, (pub,amt)), R)[0])

        assert total_in > 0
        assert total_in == total_out

        # Then simulate insert each of the new outputs
        assert len(outs) == len(outPs)
        for i, (out, P) in enumerate(zip(outs, outPs)):
            R = self.reconstruct(d0, P)
            if R:
                (_dTxi, _), _ = self.search(((dTx,i), None), R)
                assert _dTxi != (dTx,i)
            d0 = self.digest(self.insert(((dTx,i),out), R)[0])

        return d0



class Block():
    def __init__(self, window=None):
        pass
    """
    Blockchain and proof-of-throughput functions
    ============================================
    """

    def digest_block(self):
        pass

    def apply_block():
        pass

    def verify_block(self, B, VO):
        pass

