from binascii import hexlify, unhexlify
import os
from collections import defaultdict
import random
import numpy as np

import proofofwork; reload(proofofwork)
from proofofwork import digest, search, insert, reconstruct, balance, verify
from proofofwork import respond, verify_response, do_work, verify_work, H
from proofofwork import MerkleSampler, verify_random
import unittest



N = 100
sampler = MerkleSampler()
values = range(N)
random.shuffle(values)
for v in values:
    index, _, _ = sampler.query(v)
    if index is None: sampler.insert(v)
    index, proof, N = sampler.query(v)
    assert index is not None

for i in range(100):
    iv = os.urandom(20)
    v, proof, N = sampler.random(iv)
    d0 = sampler.digest()
    verify_random(d0, iv, proof, N)

table = {}
k = 128
sampler = MerkleSampler()

for i in (3,5,8,6,4,11):
    table[H(i)] = i
    sampler.insert(H(i))

for i in range(100):
    iv = H(hexlify(os.urandom(20)))
    acc, proof, data, N = respond(iv, sampler, table.get)
    assert verify_response(sampler.digest(), iv, proof, data, N) == acc



class TestUniform(unittest.TestCase):
    pass


N = 1000
sampler = MerkleSampler()
values = range(N)
table = {}
random.shuffle(values)
for v in values: 
    table[H(v)] = v
    sampler.insert(H(v))

while True:
    threshold = 1<<(256-6)
    k = 128
    d0 = sampler.digest()
    iv = H(hexlify(os.urandom(20)))
    acc, proofs, N = do_work(sampler, iv, k, table.get)
    if long(acc,16) < threshold:
        print acc
        assert verify_work(d0, proofs, acc, N, k, threshold)
        break

def test_uniform(N=N, iters=10000):
    histogram = np.zeros(N)
    global realrandom
    realrandom = np.zeros(N)

    for i in range(iters):
        iv = H(hexlify(os.urandom(20)))
        acc, proof, data, N = respond(iv, sampler, table.get)
        (_, ((k,_), _, _)) = proof[-1]
        histogram[table[k]] += 1
        realrandom[np.random.randint(N)] += 1

    histogram = sorted(histogram) / np.sum(histogram)
    realrandom = sorted(realrandom) / np.sum(realrandom)

    return histogram

import time
def test_speed():
    global times, Ns, inserts, sampler
    max_exp = 20
    x = np.arange(2,max_exp)
    #Ns = 2**x
    Ns = 100*x
    values = range(2**max_exp)
    sampler = MerkleSampler()
    random.shuffle(values)
    total = 0
    times = []
    inserts = []
    R = random.Random(os.urandom(20))
    for N in Ns:
        t0 = time.clock()
        for i in range(total,N):
            v = values[i]
            table[H(v)] = v
            sampler.insert(H(v))
        t1 = time.clock()
        inserts += (t1-t0)/(N-total)
        print N, (t1-t0)/(N-total)
        total = N
        iters = 10000
        t0 = time.clock()
        for i in range(iters):
            sampler.random(R.random())
        t1 = time.clock()
        times.append((t1-t0)/iters)
        print N, (t1-t0)/iters
    return x, Ns, times
        

values = range(N)
sampler = MerkleSampler()
table = {}
random.shuffle(values)
for v in values: 
    table[H(v)] = v
    sampler.insert(H(v))
    

hist = test_uniform()

if __name__ == "__main__":
    unittest.main()
