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
from Crypto.Hash import SHA256


H = lambda x: SHA256.new(str(x)).hexdigest()
MS = MerkleSampler(H)
get_random = MS.get_random
verify_random = MS.verify_random

"""
get_random() and verify_random():
    A random elements is selected from a sampler DA as follows:

        element, VO = get_random(seed, DA)

    where VO is the O(log N) verification object (a trace through the
    Merkle tree)

    The selection can be verified in O(log N) worst-case time using:
    
        verify_random(d0, element, seed, VO)

    where d0 = digest(DA)
"""



def do_work(iv, k, (D,A), lookup):
    """
    1. Initialize an accumulator with 'iv'. 
    2. Using the current accumulator value as the as the seed to a PRF, 
       draw a random element from the set.
    3. Add the data for this element into the accumulator.
    4. Repeat (from 2) for k iterations.

    The final value of the accumulator is the proof-of-work, which can be 
    compared to a difficulty threshold, a la Bitcoin.

    A verifier with only O(1) of state (the root hash) can verify the work
    using the O(k * log N) verification object.

    The prover walks the verifier backwards through the work, beginning 
    with the final accumulator value. This means a malicious prover would
    have to expend O(2^k * log N) effort to make the verifier expend
    O(k * log n). (This is a claim about DoS resistance)

    A verifier with O(N) of state (such as another worker) can verify the
    solution for theirself using O(k * log N) effort and only O(1)
    communication (just the iv). However it may still be preferable to
    require an O(k) proof object for DoS resistance, as described above.
    """
    acc = iv
    walk = []  # Collect the verification objects in reverse order
    for _ in range(k):
        # Draw a random element (and corresponding VO)
        element, (VO, _) = get_random(acc, (D,A))
        data = lookup(element)
        walk.insert(0, (acc, VO, data))

        # Add the data for this iteration into the accumulator
        acc = H((acc, data))

    return acc, (walk, len(A))


def verify_work(d0, acc, (walk, N), k):
    """
    Walk backwards through the work using the O(k * log N) verification 
    object.
    """
    assert len(walk) == k
    for (prev_acc, VO, data) in walk:
        v = H(data)
        assert verify_random(d0, v, prev_acc, (VO,N))
        assert acc == H((prev_acc, data))
        acc = prev_acc

    return True
