"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012


A Proof-of-Throughput scheme is a tuple 

     (F, Sample, Verify) 

where F is a function that a Server wants to prove it can evaluate many times
within some time interval, i.e. at a minimum throughput. The Client gives the
client a random string as a puzzle challenge - the server has to evaluate the
function T times (on average) in order to find a winning solution.

The effectiveness of this scheme is controlled by a parameter k, such that the 
Verifier requires O(k) effort to verify a winning solution, and an adversary 
that only evaluates F(d) for a subset of its domain (M/N) will have to 
expend O(T * (M/N)^k) effort to produce a winning solution.


Some suggested instantiations of this scheme:

- A cloud storage provider can use this to demonstrate the fault tolerance 
  of its data layout[1], similar to 1.

- Bitcoin currently uses proof-of-throughput to a Hash function evaluator

- My proposed alternative is to create proofs-of-throughput to the 'unspent-
  coins' database, which is necessary for validating transactions.


[1] How to Tell if Your Cloud Files are Vulnerable to Drive Crashes. 
    Bowers, Dijk, Juels, Oprea, and Rivest. 2011
    http://www.rsa.com/rsalabs/staff/bios/kbowers/publications/RAFT.


Notation
========

F: D -> R

     F is the function that we want to demonstrate queries-per-second 
     access to. Its domain is D and its range is R.


Sample: String -> D

     A deterministic PRF that accepts a string as a seed and produces 
     random elements uniformly from D.


Verify: D -> R -> {True,False}

     A verify function that returns True if-and-only-if the result is
     correct, that is, if

         r == F(d) 

"""


from Crypto.Hash import SHA256
H = lambda x: SHA256.new(str(x)).hexdigest()[:8]


def do_work(iv, nonce, k, F, Sample):
    """
    1. Initialize an accumulator with 'iv'. 
    2. Using the current accumulator value as the as the seed to a PRF, 
       select a random element from the set.
    3. Add the data for this element into the accumulator.
    4. Repeat (from 2) for k iterations.

    The final value of the accumulator is the proof-of-work, which can be
    compared to a difficulty threshold, a la Bitcoin.

    """
    acc = H((iv, nonce))
    walk = []  # Collect the verification objects in reverse order

    for _ in range(k):

        # Draw a random element from the domain of F
        d = Sample(acc)

        # Evaluate F and accumulate the result
        r = F(d)
        walk.insert(0, (acc, r))
        acc = H((acc, r))

    return nonce, acc, walk


def verify_work(iv, k, solution, Verify, Sample, threshold=1<<256):
    """
    The prover walks the verifier backwards through the work, beginning 
    with the final accumulator value. This means a malicious prover would
    have to expend O(2^k) effort to make the verifier expend O(k).
    """
    nonce, acc, walk = solution
    assert len(walk) == k
    assert long(acc, 16) <= threshold

    for (prev, r) in walk:
        d = Sample(prev)
        assert Verify(d, r)
        assert acc == H((prev, r))
        acc = prev

    assert prev == H((iv,nonce))
    return True


"""
Examples
========
"""

import random
PRF = lambda seed: random.Random(seed)


def SortThroughput(N, M):
    """
    Prove how fast you can sort lists of N elements (integers from from 0..M)
    """
    F = lambda d: sorted(d)
    def Sample(seed):
        prf = PRF(seed)
        return [prf.randint(0,M-1) for _ in range(N)]
    Verify = lambda d, r: F(d) == r

    return F, Sample, Verify


def HashThroughput():
    """
    Prove how fast you can compute hashes
    """
    F = lambda d: SHA256.new(d).hexdigest()
    Sample = lambda seed: seed
    Verify = lambda d, r: F(d) == r

    return F, Sample, Verify


from redblack import AuthSelectRedBlack
ASRB = AuthSelectRedBlack(H)
size = ASRB.size
digest = ASRB.digest
select = ASRB.select
verify = ASRB.verify

def RedBlackSelectThroughput(D):
    """
    Prove how fast you can access the 'select' operation for the provided
    tree.
    """
    N = size(D)
    d0 = digest(D)

    F = lambda d: select(d, D)
    Sample = lambda seed: PRF(seed).randint(0, N-1)
    Verify = lambda d, (v,P): verify(d0, v, d, P)

    return F, Sample, Verify


"""

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

"""
