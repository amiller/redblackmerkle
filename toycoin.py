"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012


An alternate proof-of-work scheme for Bitcoin. Instead of merely computing
hashes, miners compete by demonstrating high-throughput access to their
database of 'unspent coins'.

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
    The Unspent Coins database. It's an AuthSelectRedBlackTree.

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

"""

from proofofthroughput import do_work, verify_work
from redblack import AuthSelectRedBlack

import random
PRF = lambda seed: random.Random(seed)

from Crypto.Hash import SHA256
H = lambda x: '' if not x else SHA256.new(str(x)).hexdigest()[:8]

ASRB = AuthSelectRedBlack(H)
size = ASRB.size
search = ASRB.search
digest = ASRB.digest
select = ASRB.select
verify = ASRB.verify
insert = ASRB.insert
delete = ASRB.delete
reconstruct = ASRB.reconstruct


class ToyCoin():
    def __init__(self, verify_signature):
        self.verify_signature = verify_signature
        

    def digest_transaction(self, Tx):
        (inps, outps, sigs) = Tx
        return H((inps, outps))  # Exclude sig from the digest


    def query_unspent(self, inp, D):
        P = search((inp, ('',0)), D)
        if not P: return None, P
        for _, ((_inp, (pub, amt)), _, _) in P[::-1]:
            if _inp == inp: return ((pub, amt), P)
        return None, P


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
            v, P = self.query_unspent(inp, D)
            # D = delete((inp,v), D)
            inpPs.append(P)

        # Then insert each of the new outputs
        outPs = []
        for i, v in enumerate(outs):
            P = search(((dTx,i), ('',0)), D)
            D = insert(((dTx,i),     v ), D)
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
            R = reconstruct(P)
            assert digest(R) == d0
            (pub, amt), _P = self.query_unspent(inp, R)
            assert P == _P
            assert self.verify_signature(dTx, pub, sig)
            assert amt > 0
            total_in += amt
            # d0 = digest(delete((inp, (pub,amt)), R))

        assert total_in > 0
        assert total_in == total_out

        # Then simulate insert each of the new outputs
        assert len(outs) == len(outPs)
        for i, (out, P) in enumerate(zip(outs, outPs)):
            R = reconstruct(P)
            assert digest(R) == d0
            _out, _P = self.query_unspent((dTx,i), R)
            assert out != _out
            d0 = digest(insert(((dTx,i),out), R))

        return d0
