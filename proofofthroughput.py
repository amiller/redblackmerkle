"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012


A Proof-of-Throughput scheme is a way for a Server to prove to its Clients
that it is able to perform a computation F very efficiently. The scheme is a
tuple:

     (F, Sample, Verify) 

where F is the function that the Server wants to prove it can evaluate many 
times within some time interval, i.e. at a minimum throughput. The Client gives 
the Server a random string as a puzzle and a challenge T - the server has to 
evaluate F an average of T times in order to find a puzzle solution.

The effectiveness of this scheme is controlled by a parameter k, such that the
Verifier requires O(k) effort to verify a winning solution, but an adversary 
with faulty hardware (fails with probability e) has to perform O(e^k) 
operations.


Some suggested instantiations of this scheme:

- A cloud storage provider can use this to demonstrate the fault tolerance
  of its data layout[1], similar to 1.

- You could prove you have access to a very fast number-sorter? GPU benchmarks...

- Bitcoin currently uses proof-of-throughput to a Hash function evaluator, in
  so many words (analysis to come, hopefully).

- My proposed alternative to Bitoin is to create proofs-of-throughput to the 
  'unspent-coins' database, which is what's necessary for validating 
  transactions. Many miners currently don't bother to maintain one. This is a 
  better way utilization of the proof-of-work scheme.


[1] How to Tell if Your Cloud Files are Vulnerable to Drive Crashes. 
    Bowers, Dijk, Juels, Oprea, and Rivest. 2011
    http://www.rsa.com/rsalabs/staff/bios/kbowers/publications/RAFT.



Notation
========

F: D -> R

     F is the function that we want to demonstrate queries-per-second 
     access to. Its domain is D and its range is R.


Sample: String -> D

     A deterministic PRNG that accepts a string as a seed and produces 
     random elements uniformly from D.


Verify: D -> R -> {True,False}

     A verify function that returns True if-and-only-if the result is
     correct, that is, if

         r == F(d) 

"""


from Crypto.Hash import SHA256
H = lambda x: '' if not x else SHA256.new(str(x)).hexdigest()[:8]


def do_work(iv, nonce, k, F, Sample):
    """
    1. Initialize an accumulator with (iv,nonce). 
    2. Using the accumulator value as the as a seed to a PRNG
       select a random element, d, from the domain of F.
    3. Add the result of F(d) into the accumulator.
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
PRNG = lambda seed: random.Random(seed)


def SortThroughput(N, M):
    """
    Prove how fast you can sort lists of N elements (integers from from 0..M)
    """
    F = lambda d: sorted(d)
    def Sample(seed):
        prng = PRNG(seed)
        return [prng.randint(0,M-1) for _ in range(N)]
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


from redblack import RedBlack
RB = RedBlack(H)
digest = RB.digest
select = RB.select
verify = RB.verify
search = RB.search
size = RB.size

def RedBlackSelectThroughput(D):
    """
    Prove how fast you can access the 'select' operation for the provided
    tree.
    """
    N = size(D)
    d0 = digest(D)

    F = lambda d: search(select(d, D), D)
    Sample = lambda seed: PRNG(seed).randint(0, N-1)
    Verify = lambda d, R: verify(d0, R) and search(select(d, R), R) == R

    return F, Sample, Verify
