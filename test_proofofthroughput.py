import os
from binascii import hexlify, unhexlify
import numpy as np
import unittest
import random
import time

import redblack; reload(redblack)
import proofofthroughput; reload(proofofthroughput)
from proofofthroughput import do_work, verify_work
from proofofthroughput import select, H, RB, PRNG
from proofofthroughput import RedBlackSelectThroughput
from proofofthroughput import SortThroughput
from proofofthroughput import HashThroughput

insert = RB.insert
digest = RB.digest
search = RB.search
delete = RB.delete
record = RB.record
replay = RB.replay
size = RB.size

class RedBlackSelectThroughputTest(unittest.TestCase):
    def setUp(self):
        values = range(1000)
        random.shuffle(values)
        table = {}
        D = ()
        for v in values: 
            table[H(v)] = v
            D = insert(H(v), D)
        k = 64
        N = size(D)
        self.table = table
        self.D = D
        d0 = digest(D)

        # Construct the proof of work functions
        def F(d):
            T = record(D)
            v = T.select(d)
            T.delete(v)
            data = table[v]
            return (data, T.VO)
        self.F = F

        self.Sample = lambda seed: PRNG(seed).randint(0, N-1)

        def Verify(d, r):
            (data, VO) = r
            T = replay(d0, VO)
            v = T.select(d)
            T.delete(v)
            assert H(data) == v
            return True
        self.Verify = Verify


    def test_work(self):
        k = 32
        for i in range(100):
            iv = ''
            nonce = H(os.urandom(20))
            solution = do_work(iv, nonce, k, self.F, self.Sample)
            assert verify_work(iv, k, solution, self.Verify, self.Sample)


    def test_work_with_threshold(self):
        """
        Simulate the Bitcoin proof of work scheme, where the work needs
        to satisfy a threshold constraint in order to show that it was
        performed a large number of times.

        The threshold should be set as

            thresh = (1<<256) / (T/k)

        where (1<<256) is the largest possible value for the accumulator.
        The worker will have to call do_work() an average of T/k times 
        (and thus evaluate F() an average of T times), while the verifier
        will only need to evaluate the winning work once.

        """
        # Produce a hash with two 0's in the front of the digest
        k = 32
        T = 8192
        thresh = (1<<256) * k / T
        while True:
            iv = ''
            nonce = H(os.urandom(20))
            S = do_work(iv, nonce, k, self.F, self.Sample)
            (_, acc, _) = S
            if long(acc, 16) < thresh:
                assert verify_work(iv, k, S, self.Verify, self.Sample, thresh)
                print 'Found a winning ticket:', acc
                break


class ProofOfThroughputTest(unittest.TestCase):
    def _test_proofofwork(self, F, Sample, Verify, notes):
        # Produce a hash with two 0's in the front of the digest
        k = 8
        T = 2048
        thresh = (1<<32) * k / T - 1
        iv = H(os.urandom(20))
        print "Proof-of-Throughput Challenge"
        print notes['name']
        print "The domain of F is: ", notes['domain']
        print "F(d) produces: ", notes['function']
        print "Our challenge is to find a winning ticket < 0x%08x" % thresh
        print "Starting with iv:", iv
        print
        count = 0
        while True:
            count += 1
            nonce = H(os.urandom(20))
            S = do_work(iv, nonce, k, F, Sample)
            (_, acc, walk) = S
            if long(acc, 16) < thresh:
                assert verify_work(iv, k, S, Verify, Sample, thresh)
                print 'Winning ticket found:', acc
                print 'Nonce:', nonce
                print 'The k problems we solved in this iteration were:'
                for (prev, r) in walk:
                    print 'Sample(%s...) -> %s   F(d) = %s' % \
                        (prev[:8], Sample(prev), r)
                print
                print 'In total, it took %d calls to F()' % (count*k)
                print ('Compared to the expected number (%d), it took us a '
                       'factor of %.2fx' % (T, float(count*k)/T))
                break

    def test_SortThroughput(self):
        N = 10
        notes = dict(name="Sorting N elements", 
                     domain="tuples of N=%d integers from 0..100" % N,
                     function="sorted(d)")
        
        F, Sample, Verify = SortThroughput(N, 100)
        self._test_proofofwork(F, Sample, Verify, notes)

    def test_RedBlackThroughput(self):
        N = 10
        values = range(N)
        random.shuffle(values)
        D = ()
        for i in values: D = insert(i, D)

        notes = dict(name="Selecting from an ordered set, including the "
                     "Merkle tree path",
                     domain="integers 1..%d" % N,
                     function="search(select(i, D), D)")

        F, Sample, Verify = RedBlackSelectThroughput(D)
        self._test_proofofwork(F, Sample, Verify, notes)



if __name__ == "__main__":
    unittest.main()
