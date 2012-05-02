from sampler import MerkleSampler
import json
from Crypto.Hash import SHA256


H = lambda x: SHA256.new(str(x)).hexdigest()
MS = MerkleSampler(H)
ARB = MS.ARB
digest = MS.digest
insert = MS.insert
query = MS.query
random = MS.random
verify_random = MS.verify_random


def do_work(iv, k, (D,A), lookup):
    acc = iv
    walk = []
    for _ in range(k):
        (v,_), (P,_) = random(acc, (D,A))
        data = lookup(v)
        walk.insert(0, (acc, P, data))
        acc = MS.H(acc, data)
    return acc, (walk, len(A))


def verify_work(d0, acc, (walk, N), k, threshold=1<<(256-16)):
    assert long(acc, 16) < threshold
    assert len(walk) == k

    for (seed, P, data) in walk:
        v = H(data)
        assert verify_random(d0, v, seed, (P,N))
        assert acc == MS.H(seed, data)
        acc = seed

    return True
