import os
import unittest
import sampler; reload(sampler)
from sampler import MerkleSampler
import random
from Crypto.Hash import SHA256

H = lambda x: SHA256.new(x).hexdigest()
MS = MerkleSampler(H)
ARB = MS.ARB
digest = MS.digest
insert = MS.insert
simulate_insert = MS.simulate_insert
query = MS.query
get_random = MS.get_random
verify_random = MS.verify_random

class SamplerTest(unittest.TestCase):
    def test_sampler(self):
        N = 100
        DA = (),[]
        values = range(N)
        random.shuffle(values)
        for v in values:
            index, PN = query(v, DA)
            d0 = digest(DA)
            if index is None: 
                DA = insert(v, DA)
                assert digest(DA) == simulate_insert(d0, v, PN)
            index, _ = query(v, DA)
            assert index is not None

        for _ in range(100):
            seed = os.urandom(20)
            v, PN = get_random(seed, DA)
            d0 = digest(DA)
            verify_random(d0, v, seed, PN)

N = 100
DA = (), []
values = range(N)
random.shuffle(values)
for v in values: 
    DA = insert(v, DA)

def test_uniform(iters=10000):
    global realrandom, histogram
    histogram = N*[0]
    realrandom = N*[0]

    for _ in range(iters):
        seed = H(os.urandom(20))
        v, _ = get_random(seed, DA)
        histogram[v] += 1
        realrandom[random.randint(0,N-1)] += 1

    histogram = sorted(histogram)   # / sum(histogram)
    realrandom = sorted(realrandom) # / sum(realrandom)
test_uniform()


import time
def test_speed():
    global times, Ns, inserts, sampler
    max_exp = 20
    x = range(2,max_exp)
    #Ns = 2**x
    Ns = 100*x
    values = range(2**max_exp)
    DA = (), []
    random.shuffle(values)
    total = 0
    times = []
    inserts = []
    R = random.Random(os.urandom(20))
    for N in Ns:
        t0 = time.clock()
        for v in values[total:N]:
            DA = insert(v, DA)
        t1 = time.clock()
        inserts += (t1-t0)/(N-total)
        print 'insertion:', N, (t1-t0)/(N-total)
        total = N
        iters = 10000
        t0 = time.clock()
        for i in range(iters):
            get_random(R.random(), DA)
        t1 = time.clock()
        times.append((t1-t0)/iters)
        print 'draw random:', N, (t1-t0)/iters
    return x, Ns, times
#test_speed()


if __name__ == '__main__':
    unittest.main()
