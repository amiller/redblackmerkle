"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012


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
from redblack import SelectRedBlack

import random
PRNG = lambda seed: random.Random(seed)

from Crypto.Hash import SHA256


class Transaction():

    def __init__(self, verify_signature, block_window=None):
        self.H = lambda x: '' if not x else SHA256.new(str(x)).hexdigest()[:8]
        self.RB = SelectRedBlack(self.H)
        self.verify_signature = verify_signature
        self.block_window = block_window


    def digest_transaction(self, Tx):
        (inps, outps, sigs) = Tx
        return self.H((inps, outps))  # Exclude sig from the digest


    def apply_transaction(self, d0, Tx, proof):
        search = self.RB.search
        delete = self.RB.delete
        insert = self.RB.insert

        (inps, outs, sigs) = Tx
        dTx = self.digest_transaction(Tx)

        D = proof.next()

        total_out = sum(amt for (_, amt) in outs)
        total_in = 0

        # First remove each of the old inputs
        for inp, sig in zip(inps, sigs):
            (_inp, (pub, amt)), _ = search((inp, None), D)
            assert _inp == inp
            assert self.verify_signature(dTx, pub, sig)
            assert amt > 0
            total_in += amt
            out = (pub,amt)
            D = proof.send(delete((inp, out), D))

        assert total_in > 0
        assert total_in == total_out

        # Then insert each of the new outputs
        for i, out in enumerate(outs):
            inp = (dTx,i)
            if D:
                (_dTxi, _), _ = search((inp, None), D)
                assert _dTxi != inp
            D = proof.send(insert((inp, out), D))

        return D
