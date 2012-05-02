from Crypto.Hash import SHA256
import json
import os
import random

from binascii import hexlify, unhexlify
bytes_to_long = lambda b: long(hexlify(b), 16)


import authredblack; reload(authredblack)
from authredblack import AuthRedBlack

H = lambda *args: SHA256.new(json.dumps(args)).hexdigest()

ARB = AuthRedBlack(H)
digest = ARB['digest']
search = ARB['search']
insert = ARB['insert']
reconstruct = ARB['reconstruct']
balance = ARB['balance']
verify = ARB['verify']


# Replace with a CSPRF
def random_index(seed, N):
    return random.Random(seed).randint(0,N-1)


def verify_random(d0, seed, proof, N):
    D = reconstruct(iter(proof))
    assert(H(digest(D),N) == d0)
    (_, ((v,i), _, _)) = proof[-1]
    assert i == random_index(seed, N)
    assert proof == search((v,i), D)
    return True


class MerkleSampler():
    def __init__(self):
        self.D = ()
        self.array = []

    def insert(self, v):
        # Add new elements to the end of the array at position
        # i = len(array). Add (v,i) to the tree.
        i, proof, _ = self.query(v)
        N = len(self.array)
        assert i is None, "Trying to insert duplicate %s" % k
        self.D = insert((v,N), self.D)
        self.array.append(v)
        return proof, N

    def query(self, v):
        proof = search((v,0), self.D)
        N = len(self.array)
        if not proof: return None, proof, N
        (_, ((_v,i), _, _)) = proof[-1]
        if _v == v: return i, proof, N
        return None, proof, N

    def digest(self):
        return H(digest(self.D), len(self.array))

    def random(self, seed):
        N = len(self.array)
        i = random_index(seed, N)
        v = self.array[i]
        proof = search((v,i), self.D)
        return v, proof, N

    def delete(self, v):
        raise NotImplemented
        i, proofA, _ = self.query(v)
        proofA = search(q, self.D)


def respond(acc, sampler, lookup):
    # Use the provided nonce as a seed to our PRF
    v, proof, N = sampler.random(acc)
    data = lookup(v)

    # Add the data into the accumulator
    acc = H(acc, data)
    return acc, proof, data, N


def verify_response(d0, acc, proof, data, N):
    r = reconstruct(iter(proof))
    assert H(digest(r),N) == d0
    i = random_index(acc, N)
    v = H(data)
    assert proof == search((v,i), r)
    (_, (_vi, _, _)) = proof[-1]
    assert _vi == (v,i)
    return H(acc, data)


def do_work(sampler, iv, k, lookup):
    acc = iv
    proofs = []
    N = len(sampler.array)
    for _ in range(k):
        iv = acc
        acc, proof, data, _ = respond(iv, sampler, lookup)
        proofs = [(iv, proof, data)] + proofs # Prepend this proof
    return acc, proofs, N


def verify_work(d0, proofs, acc, N, k, threshold=1<<(256-16)):
    assert long(acc, 16) < threshold
    assert len(proofs) == k
    for iv, proof, data in proofs:
        assert verify_response(d0, iv, proof, data, N) == acc
        acc = iv
    return True
