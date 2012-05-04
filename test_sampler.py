import os
import unittest
import sampler; reload(sampler)
from sampler import MerkleSampler
import random
from Crypto.Hash import SHA256

PRF = lambda seed: random.Random(seed)

H = lambda x: SHA256.new(str(x)).hexdigest()
MS = MerkleSampler(H)
ARB = MS.ARB
digest = MS.digest
insert = MS.insert
simulate_insert = MS.simulate_insert
query = MS.query
select = MS.select
verify = MS.verify

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
            if index is None:
                print 'index is None'
                print v
                print DA
                print query(v, DA)
                print index
            assert index is not None

        d0 = digest(DA)
        _,N = d0
        for _ in range(100):
            i = PRF(os.urandom(20)).randint(0,N-1)
            v, P = select(i, DA)
            verify(d0, v, i, P)


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
    R = PRF(os.urandom(20))
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
            select(R.randint(0,N-1), DA)
        t1 = time.clock()
        times.append((t1-t0)/iters)
        print 'draw random:', N, (t1-t0)/iters
    return x, Ns, times
#test_speed()


if __name__ == '__main__':
    unittest.main()
