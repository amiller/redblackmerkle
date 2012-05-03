import os
from binascii import hexlify, unhexlify
import numpy as np
import unittest
import random
import time

import proofofwork; reload(proofofwork)
from proofofwork import do_work, verify_work, sampler_worker
from proofofwork import select, verify_query, H, MS, PRF

insert = MS.insert
query = MS.query
digest = MS.digest


def build_cheating_table(DA, lookup):
    """
    Attempt to cheat at the work by building a function that's
    fast at solving the work puzzles, but that can't be used to
    validate queries with proportionally good efficiency.

    This approach involves building an O(N * log N) table that
    can be used to solve work faster. This is a tradeoff of
    increased storage for faster time. The proof-of-work only
    really measures time, so this is what a Bitcoin miner would
    want to do optimize their payout.

    The do_work() function below is faster because it doesn't
    actually access the tree.

    TODO: Finish this note

    However, this attempt at cheating still results in O(log N)
    lookups, as shown in the construction of verify_query.

    In other words if you have oracle access to select() then
    you can build a verifier.

    -- So, why not just exercise the array?
    -- What about update costs?
    
    """

    D,A = DA
    table = {}
    N = len(A)
    for i in range(N):
        v = A[i]
        data = lookup(v)
        _, VO = query(v, DA)
        table[i] = (data, VO)

    
    print 'Built table'
    def get_random_element(seed):
        i = PRF(seed).randint(0,N-1)
        return table[i]

    return get_random_element


class ProofOfWorkTest(unittest.TestCase):
    def setUp(self):
        values = range(1000)
        random.shuffle(values)
        self.table = {}
        self.k = 64
        self.DA = (), []

        for v in values: 
            self.table[H(v)] = v
            self.DA = insert(H(v), self.DA)

    def test_cheat_at_work(self):
        # Build the lookup table
        DA, table = self.DA, self.table

        normal_worker = sampler_worker(DA, table.get)
        cheating_worker = build_cheating_table(DA, table.get)

        ivs = [H(os.urandom(20)) for _ in xrange(1000)]
        k = 16
        d0 = digest(DA)

        def verify(worker):
            for iv in ivs:
                acc, PN = do_work(iv, k, worker)
                assert verify_work(d0, acc, PN, k)

        def timeit(worker):
            t0 = time.clock()
            for iv in ivs:
                acc, PN = do_work(iv, k, worker)
            t1 = time.clock()
            return (t1-t0)/len(ivs)

        print "Normal work (s):", timeit(normal_worker)
        print "Faster work (s):", timeit(cheating_worker)


    def test_work(self):
        worker = sampler_worker(self.DA, self.table.get)
        d0 = MS.digest(self.DA)
        k = 32

        for i in range(100):
            iv = H(os.urandom(20))
            acc, PN = do_work(iv, k, worker)
            assert verify_work(d0, acc, PN, k)


    def test_work_with_threshold(self):
        """
        Simulate the behavior of a Bitcoin miner.
        """
        worker = sampler_worker(self.DA, self.table.get)
        d0 = MS.digest(self.DA)
        k = 32

        # Produce a hash with two 0's in the front
        threshold = 1<<(256-8)
        while True:
            iv = H(os.urandom(20))
            acc, VO = do_work(iv, k, worker)
            if long(acc,16) < threshold:
                print 'Found winning block:', acc
                assert verify_work(d0, acc, VO, k)
                break


if __name__ == "__main__":
    unittest.main()
