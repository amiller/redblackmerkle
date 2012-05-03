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
verify_query = MS.verify_query

"""
select() and verify_select():
    A random element is selected from a sampler DA as follows:

        i = randint(0, N-1)
        element, VO = select(i, DA)

    where VO is the O(log N) verification object (a trace through the
    Merkle tree)

    The selection can be verified in O(log N) worst-case time using:
    
        verify_query(d0, element, i, VO)

    where d0 = digest(DA)
"""

def sampler_worker(DA, lookup):
    N = len(DA[1])
    def get_random_element(seed):
        i = PRF(seed).randint(0, N-1)
        element, VO = select(i, DA)
        data = lookup(element)
        return data, VO
    return get_random_element


def do_work(iv, k, get_random_element):
    """
    1. Initialize an accumulator with 'iv'. 
    2. Using the current accumulator value as the as the seed to a PRF, 
       draw a random element from the set.
    3. Add the data for this element into the accumulator.
    4. Repeat (from 2) for k iterations.

    The final value of the accumulator is the proof-of-work, which can be 
    compared to a difficulty threshold, a la Bitcoin.
    """
    acc = iv
    walk = []  # Collect the verification objects in reverse order
    for _ in range(k):
        # Draw a random element (and its corresponding proof object)
        data, VO = get_random_element(acc)
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
    O(k * log n). (This is a claim about DoS resistance)
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


def random_oracle_O1_verifier(get_random_element):
    """
    A verifier with O(N) of state (such as another worker) can verify the
    solution for theirself using O(k * log N) effort and only O(1)
    communication (just the iv). 
    """
    def verify_work(d0, acc, iv, k):
        (_acc, _) = do_work(iv, k, get_random_element)
        assert _acc == acc
        return True
    return verify_work    


def random_oracle_Ok_verifier(get_random_element):
    """
    However it is still be preferable to require an O(k) verification
    object (just the k accumulator values) for DoS resistance, as 
    described above.
    """
    def verify_work(d0, acc, walk, k):
        (_,N) = d0
        assert len(walk) == k
        for prev_acc in walk:
            data, VO = get_random_element(prev_acc)
            assert acc == H((prev_acc, data, VO))
            acc = prev_acc
        return True

