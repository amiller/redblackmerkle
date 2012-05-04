"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012

An alternate proof-of-work scheme for Bitcoin. Instead of merely computing
hashes, miners compete by demonstrating high-throughput access to their
database of 'unspent coins'. 

This is achieved by using storing each 'unspent coin' in a MerkleSampler, 
an Authenticated Data Structure that supports uniform selection of a
random element from the set.

"""

from sampler import MerkleSampler
import json
import random
from Crypto.Hash import SHA256

PRF = lambda seed: random.Random(seed)
H = lambda x: SHA256.new(str(x)).hexdigest()
MS = MerkleSampler(H)
select = MS.select
verify = MS.verify

"""
select() and verify():
    A random element is selected from a sampler DA as follows:

        i = randint(0, N-1)
        element, VO = select(i, DA)

    where VO is the O(log N) verification object (a trace through the
    Merkle tree)

    The selection can be verified in O(log N) worst-case time using
    the verification object:
    
        verify(d0, element, i, VO)

    where d0 = digest(DA).
"""

def do_work(iv, k, DA, lookup):
    """
    1. Initialize an accumulator with 'iv'. 
    2. Using the current accumulator value as the as the seed to a PRF, 
       select a random element from the set.
    3. Add the data for this element into the accumulator.
    4. Repeat (from 2) for k iterations.

    The final value of the accumulator is the proof-of-work, which can be
    compared to a difficulty threshold, a la Bitcoin.

    """
    acc = iv
    walk = []  # Collect the verification objects in reverse order
    N = len(DA[1])
    for _ in range(k):
        # Draw a random element (and its corresponding proof object)
        i = PRF(acc).randint(0, N-1)
        element, VO = select(i, DA)
        data = lookup(element)
        walk.insert(0, (acc, data, VO))
        acc = H((acc, data, VO))

    return (acc, walk)


def verify_work(d0, acc, walk, k):
    """
    A verifier with only O(1) of state (the root hash) can verify the work
    using the O(k * log N) verification object.

    The prover walks the verifier backwards through the work, beginning 
    with the final accumulator value. This means a malicious prover would
    have to expend O(2^k * log N) effort to make the verifier expend
    O(k * log N). (This is a claim about DoS resistance)
    """
    assert len(walk) == k
    (_, N) = d0
    for (prev_acc, data, VO) in walk:
        i = PRF(prev_acc).randint(0, N-1)
        v = H(data)
        assert verify_query(d0, v, i, VO)
        assert acc == H((prev_acc, data, VO))
        acc = prev_acc

    return True


def blackbox_O1_query_verifier(selector):
    """
    A verifier that can evaluate select() on arbitrary inputs can
    simulate (verify) a query using only O(1) input (the array index) and
    O(log N) effort.
    """
    def verify_query(d0, v, i):
        data, VO = selector(i)
        assert verify(d0, v, i, VO)
        return True

    return verify_query
